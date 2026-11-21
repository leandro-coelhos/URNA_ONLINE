"""Recibo da #6: autenticação, inclusão, ataques e falhas após gravação.

RSA e arquivos JSONL são reais; as cifras pequenas são sintéticas para testar
os contratos. O cenário com ElGamal real fica em test_crypto_integration.py.
As chaves privadas temporárias só existem no processo que simula os papéis.
"""

import base64
from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from src.bulletin_board.board import BulletinBoard
from src.bulletin_board.hash_chain import (
    ChainIntegrityError, DuplicateVoteError, genesis_hash, make_checkpoint,
    make_record, read_records,
)
from src.crypto.ballots import (
    BALLOT_DOMAIN, IneligibleVoterError, InvalidBallotSignatureError, sign_ballot,
)
from src.crypto.keys import PublicKeyError, public_key_to_pem
from src.crypto.receipts import (
    MAX_RECEIPT_BYTES, RECEIPT_DOMAIN, InvalidReceiptSignatureError, ReceiptFormatError,
    ReceiptMismatchError, ReceiptNotFoundError, canonical_receipt_bytes,
    load_signed_receipt, sign_receipt, verify_receipt_in_board, verify_signed_receipt,
)
from src.crypto.signatures import generate_signing_key, sign_bytes, verify_bytes
from src.server.receipts import ReceiptIssuanceError, issue_receipt, publish_with_receipt


class ReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_key = generate_signing_key(2048)
        cls.server_pem = public_key_to_pem(cls.server_key.public_key())
        cls.voter_keys = {v: generate_signing_key(2048) for v in ("v1", "v2")}

    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "board.jsonl"
        self.context = {
            "election_id": "eleicao_2026", "candidate_ids": ["A", "B"],
            "voter_public_keys": {v: public_key_to_pem(k.public_key()) for v, k in self.voter_keys.items()},
        }
        self.receipt_context = {
            "election_id": "eleicao_2026", "voter_id": "v1", "server_public_key_pem": self.server_pem,
        }
        self.envelopes = {
            v: sign_ballot({
                "schema_version": 1, "election_id": "eleicao_2026", "voter_id": v,
                "ciphertexts": [
                    {"candidate_id": "A", "c1": "4", "c2": "8"},
                    {"candidate_id": "B", "c1": "16", "c2": "32"},
                ],
            }, key) for v, key in self.voter_keys.items()
        }
        self.board = BulletinBoard.create(self.path, **self.context)
        # Registro montado em memória, ainda NÃO publicado. Isso permite testar
        # que a assinatura isolada do servidor não comprova inclusão.
        self.record = make_record(
            self.envelopes["v1"], index=0, previous_hash=genesis_hash("eleicao_2026")
        )
        self.signed = sign_receipt(self.record, self.server_key)

    def publish(self, voter_id="v1"):
        return publish_with_receipt(
            self.board, self.envelopes[voter_id], server_private_key=self.server_key
        )

    def verify_in_board(self, signed, records=None, **overrides):
        context = {
            **self.context, **self.receipt_context,
            "submitted_envelope": self.envelopes["v1"], "expected_checkpoint": self.board.checkpoint,
            **overrides,
        }
        records = self.board.records() if records is None else records
        return verify_receipt_in_board(signed, records, **context)

    def resign_body(self, body):
        # Simula um servidor malicioso, que CONHECE sua própria chave e pode
        # autenticar declarações falsas. A inclusão precisa ser conferida também.
        signature = sign_bytes(RECEIPT_DOMAIN + canonical_receipt_bytes(body), self.server_key)
        return {"receipt": body, "signature": base64.b64encode(signature).decode("ascii")}

    def test_known_canonical_bytes_and_no_secret_fields(self):
        body = {**self.signed["receipt"], "record_hash": "a" * 64}
        expected = (
            b'{"election_id":"eleicao_2026","record_hash":"' + b"a" * 64
            + b'","record_index":0,"schema_version":1,"voter_id":"v1"}'
        )
        self.assertEqual(canonical_receipt_bytes(body), expected)
        self.assertEqual(set(self.signed), {"receipt", "signature"})

    def test_roundtrip_and_independent_library_verifier(self):
        parsed = load_signed_receipt(json.dumps(self.signed).encode("utf-8"))
        self.assertEqual(verify_signed_receipt(parsed, **self.receipt_context), self.signed["receipt"])
        self.server_key.public_key().verify(
            base64.b64decode(parsed["signature"]),
            RECEIPT_DOMAIN + canonical_receipt_bytes(parsed["receipt"]),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256(),
        )

    def test_json_key_order_whitespace_and_returned_copies(self):
        reordered = deepcopy(self.signed)
        reordered["receipt"] = dict(reversed(list(reordered["receipt"].items())))
        parsed = load_signed_receipt(json.dumps(reordered, indent=2))
        verified = verify_signed_receipt(parsed, **self.receipt_context)
        verified["record_hash"] = "0" * 64
        self.assertEqual(parsed, self.signed)
        self.record["ballot"]["voter_id"] = "alterado"
        self.assertEqual(self.signed["receipt"]["voter_id"], "v1")

    def test_tampering_each_signed_reference_is_rejected(self):
        changes = {"election_id": "outra_eleicao", "voter_id": "v2", "record_index": 1, "record_hash": "0" * 64}
        for field, value in changes.items():
            with self.subTest(field=field):
                changed = deepcopy(self.signed)
                changed["receipt"][field] = value
                context = dict(self.receipt_context)
                if field in ("election_id", "voter_id"):
                    context[field] = value  # Chegar à assinatura, não parar na comparação de contexto.
                with self.assertRaises(InvalidReceiptSignatureError):
                    verify_signed_receipt(changed, **context)

    def test_wrong_server_key_and_modified_signature_are_rejected(self):
        with self.assertRaises(InvalidReceiptSignatureError):
            verify_signed_receipt(self.signed, **{
                **self.receipt_context, "server_public_key_pem": self.context["voter_public_keys"]["v1"],
            })
        changed = deepcopy(self.signed)
        raw = base64.b64decode(changed["signature"])
        changed["signature"] = base64.b64encode(bytes([raw[0] ^ 1]) + raw[1:]).decode("ascii")
        with self.assertRaises(InvalidReceiptSignatureError):
            verify_signed_receipt(changed, **self.receipt_context)

    def test_domain_separates_receipt_from_ballot_signatures(self):
        canonical = canonical_receipt_bytes(self.signed["receipt"])
        self.assertFalse(verify_bytes(
            BALLOT_DOMAIN + canonical, base64.b64decode(self.signed["signature"]), self.server_pem
        ))
        wrong_domain = deepcopy(self.signed)
        wrong_domain["signature"] = base64.b64encode(
            sign_bytes(BALLOT_DOMAIN + canonical, self.server_key)
        ).decode("ascii")
        with self.assertRaises(InvalidReceiptSignatureError):
            verify_signed_receipt(wrong_domain, **self.receipt_context)

    def test_valid_receipt_from_other_context_is_rejected(self):
        for field, value in (("election_id", "outra"), ("voter_id", "v2")):
            with self.subTest(field=field), self.assertRaises(ReceiptMismatchError):
                verify_signed_receipt(self.signed, **{**self.receipt_context, field: value})

    def test_invalid_body_fields_types_and_limits(self):
        cases = [
            ("schema_version", True), ("schema_version", 2),
            ("record_index", True), ("record_index", -1), ("record_index", 2**63),
            ("record_index", 0.0), ("record_index", "0"),
            ("record_hash", "A" * 64), ("record_hash", "a" * 63), ("record_hash", None),
            ("election_id", "eleição"), ("voter_id", " v1"), ("voter_id", "a" * 65),
            ("r", "123"), ("choice", "A"), ("private_key", "segredo"),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value), self.assertRaises(ReceiptFormatError):
                canonical_receipt_bytes({**self.signed["receipt"], field: value})
        for invalid in ([], None, {k: v for k, v in self.signed["receipt"].items() if k != "record_hash"}):
            with self.subTest(invalid=invalid), self.assertRaises(ReceiptFormatError):
                canonical_receipt_bytes(invalid)

    def test_envelope_cannot_select_key_or_algorithm_and_base64_is_strict(self):
        for extra in ({"public_key": self.server_pem}, {"algorithm": "none"}):
            with self.subTest(extra=extra), self.assertRaises(ReceiptFormatError):
                verify_signed_receipt({**self.signed, **extra}, **self.receipt_context)
        for encoded in ("", "!!", "AA==\n", "AB==", "a" * 1369, None):
            with self.subTest(encoded=encoded), self.assertRaises(ReceiptFormatError):
                load_signed_receipt(json.dumps({**self.signed, "signature": encoded}))

    def test_json_rejects_duplicate_fields_at_both_levels(self):
        original = json.dumps(self.signed, separators=(",", ":"))
        cases = (
            original.replace('"receipt":', '"signature":"AA==","receipt":', 1),
            original.replace('"record_index":0', '"record_index":1,"record_index":0'),
        )
        for document in cases:
            with self.subTest(document=document), self.assertRaises(ReceiptFormatError):
                load_signed_receipt(document)

    def test_json_rejects_bad_encoding_constants_size_depth_and_root(self):
        cases = [b"\xff", "\ud800", "[]", "null", "{}", "{", b" " * (MAX_RECEIPT_BYTES + 1),
                 "é" * (MAX_RECEIPT_BYTES // 2 + 1), "[" * 1500 + "]" * 1500, 123]
        for constant in ("NaN", "Infinity", "-Infinity"):
            cases.append(json.dumps(self.signed).replace('"record_index": 0', f'"record_index": {constant}'))
        for index, document in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(ReceiptFormatError):
                load_signed_receipt(document)

    def test_largest_format_fits_reader_limit(self):
        # Teste de formato, sem gerar uma chave RSA grande desnecessariamente.
        # 1024 bytes é o comprimento de uma assinatura RSA de 8192 bits.
        maximum = {
            "receipt": {"schema_version": 1, "election_id": "e" * 64, "voter_id": "v" * 64,
                        "record_index": 2**63 - 1, "record_hash": "f" * 64},
            "signature": base64.b64encode(bytes(1024)).decode("ascii"),
        }
        serialized = json.dumps(maximum).encode("ascii")
        self.assertLess(len(serialized), MAX_RECEIPT_BYTES)
        self.assertEqual(load_signed_receipt(serialized), maximum)

    def test_signing_refuses_record_whose_hash_was_not_updated(self):
        self.record["ballot"]["ciphertexts"][0]["c2"] = "64"
        with self.assertRaises(ChainIntegrityError):
            sign_receipt(self.record, self.server_key)

    def test_publish_receipt_and_verify_from_public_files_after_reopen(self):
        signed = self.publish()
        receipt_path = Path(self.directory.name) / "receipt.json"
        receipt_path.write_text(json.dumps(signed), encoding="utf-8")
        with receipt_path.open("rb") as stream:
            loaded = load_signed_receipt(stream.read(MAX_RECEIPT_BYTES + 1))
        checkpoint = self.board.checkpoint
        reopened = BulletinBoard(self.path, **self.context, expected_checkpoint=checkpoint)
        with self.path.open("rb") as stream:
            found = self.verify_in_board(loaded, read_records(stream))
        self.assertEqual(found, reopened.records()[0])
        self.assertEqual(found["ballot"], self.envelopes["v1"]["ballot"])
        found["hash"] = "0" * 64
        self.assertNotEqual(found, reopened.records()[0])

    def test_old_receipt_remains_valid_after_another_voter_is_added(self):
        first = self.publish()
        self.publish("v2")
        self.assertEqual(self.verify_in_board(first)["index"], 0)
        self.assertEqual(self.board.checkpoint["size"], 2)

    def test_duplicate_vote_does_not_emit_another_receipt(self):
        self.publish()
        before = self.path.read_bytes()
        with patch("src.server.receipts.sign_receipt") as signer:
            with self.assertRaises(DuplicateVoteError):
                self.publish()
            signer.assert_not_called()
        self.assertEqual(self.path.read_bytes(), before)

    def test_unknown_voter_and_bad_ballot_signature_do_not_emit_receipt(self):
        unknown_ballot = {**self.envelopes["v1"]["ballot"], "voter_id": "unknown"}
        unknown = sign_ballot(unknown_ballot, self.voter_keys["v1"])
        bad = deepcopy(self.envelopes["v1"])
        bad["ballot"]["ciphertexts"][0]["c2"] = "64"
        for envelope, error in ((unknown, IneligibleVoterError), (bad, InvalidBallotSignatureError)):
            with self.subTest(error=error), patch("src.server.receipts.sign_receipt") as signer:
                with self.assertRaises(error):
                    publish_with_receipt(self.board, envelope, server_private_key=self.server_key)
                signer.assert_not_called()
        self.assertEqual(self.path.read_bytes(), b"")

    def test_invalid_server_key_is_rejected_before_publication(self):
        small_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        for key, error in ((self.server_key.public_key(), TypeError), (small_key, PublicKeyError)):
            with self.subTest(error=error), self.assertRaises(error):
                publish_with_receipt(self.board, self.envelopes["v1"], server_private_key=key)
        self.assertEqual(self.path.read_bytes(), b"")

    def test_disk_failure_does_not_sign_or_advance_checkpoint(self):
        before = self.board.checkpoint
        with patch("src.bulletin_board.board.os.fsync", side_effect=OSError("disco")):
            with patch("src.server.receipts.sign_receipt") as signer:
                with self.assertRaises(OSError):
                    self.publish()
                signer.assert_not_called()
        self.assertEqual(self.board.checkpoint, before)
        # A escrita pode ter ocorrido antes da falha de fsync. A reemissão deve
        # falhar até o operador resolver a divergência; não adotar outro hash.
        with self.assertRaises(ChainIntegrityError):
            issue_receipt(self.board, voter_id="v1", server_private_key=self.server_key)

    def test_signing_failure_preserves_vote_and_receipt_can_be_recovered(self):
        with patch("src.server.receipts.sign_receipt", side_effect=RuntimeError("assinador indisponível")):
            with self.assertRaises(ReceiptIssuanceError) as caught:
                self.publish()
        self.assertEqual(self.board.checkpoint["size"], 1)
        self.assertEqual(caught.exception.accepted_record, self.board.records()[0])
        self.assertIsInstance(caught.exception.__cause__, RuntimeError)
        before = self.path.read_bytes()
        recovered = issue_receipt(self.board, voter_id="v1", server_private_key=self.server_key)
        self.assertEqual(self.verify_in_board(recovered)["index"], 0)
        self.assertEqual(self.path.read_bytes(), before)
        with self.assertRaises(DuplicateVoteError):
            self.publish()

    def test_recovery_after_reopen_references_same_record_without_writing(self):
        original = self.publish()
        before = self.path.read_bytes()
        reopened = BulletinBoard(self.path, **self.context, expected_checkpoint=self.board.checkpoint)
        recovered = issue_receipt(reopened, voter_id="v1", server_private_key=self.server_key)
        self.assertEqual(recovered["receipt"], original["receipt"])
        verify_signed_receipt(recovered, **self.receipt_context)
        self.assertEqual(self.path.read_bytes(), before)

    def test_cannot_issue_receipt_for_unpublished_voter(self):
        with self.assertRaises(ReceiptNotFoundError):
            issue_receipt(self.board, voter_id="v1", server_private_key=self.server_key)
        self.assertEqual(self.path.read_bytes(), b"")

    def test_valid_server_signature_alone_does_not_prove_publication(self):
        verify_signed_receipt(self.signed, **self.receipt_context)
        with self.assertRaises(ReceiptNotFoundError):
            self.verify_in_board(self.signed)

    def test_validly_signed_wrong_index_or_hash_does_not_prove_inclusion(self):
        signed = self.publish()
        self.publish("v2")
        cases = (("record_index", 1, ReceiptMismatchError), ("record_hash", "0" * 64, ReceiptMismatchError),
                 ("record_index", 2, ReceiptNotFoundError))
        for field, value, error in cases:
            with self.subTest(field=field, value=value), self.assertRaises(error):
                self.verify_in_board(self.resign_body({**signed["receipt"], field: value}))

    def test_other_valid_ballot_of_same_voter_is_not_the_original_submission(self):
        signed = self.publish()
        other = deepcopy(self.envelopes["v1"]["ballot"])
        other["ciphertexts"][0]["c2"] = "64"
        other_envelope = sign_ballot(other, self.voter_keys["v1"])
        with self.assertRaises(ReceiptMismatchError):
            self.verify_in_board(signed, submitted_envelope=other_envelope)

    def test_local_envelope_from_wrong_voter_or_with_bad_signature_is_rejected(self):
        signed = self.publish()
        with self.assertRaises(ReceiptMismatchError):
            self.verify_in_board(signed, submitted_envelope=self.envelopes["v2"])
        changed = deepcopy(self.envelopes["v1"])
        changed["ballot"]["ciphertexts"][0]["c2"] = "64"
        with self.assertRaises(InvalidBallotSignatureError):
            self.verify_in_board(signed, submitted_envelope=changed)

    def test_verification_scans_records_after_the_receipt_position(self):
        signed = self.publish()
        self.publish("v2")
        records = self.board.records()
        records[1]["ballot"]["ciphertexts"][0]["c2"] = "64"
        with self.assertRaises(ChainIntegrityError):
            self.verify_in_board(signed, iter(records))

    def test_truncating_later_votes_still_fails_against_trusted_checkpoint(self):
        signed = self.publish()
        self.publish("v2")
        with self.assertRaises(ChainIntegrityError):
            self.verify_in_board(signed, self.board.records()[:1])

    def test_server_cannot_legitimize_altered_ballot_by_resigning_receipt(self):
        tampered = deepcopy(self.envelopes["v1"])
        tampered["ballot"]["ciphertexts"][0]["c2"] = "64"
        # O servidor pode refazer hashes e sua própria assinatura, mas não a
        # assinatura RSA do eleitor. Até um checkpoint escolhido pelo atacante
        # não faz o registro adulterado passar por verify_board.
        forged_record = make_record(tampered, index=0, previous_hash=genesis_hash("eleicao_2026"))
        forged_receipt = sign_receipt(forged_record, self.server_key)
        checkpoint = make_checkpoint(election_id="eleicao_2026", size=1, head_hash=forged_record["hash"])
        with self.assertRaises(InvalidBallotSignatureError):
            self.verify_in_board(forged_receipt, [forged_record], expected_checkpoint=checkpoint)

    def test_recovery_checks_integrity_of_entire_board(self):
        self.publish()
        self.publish("v2")
        content = self.path.read_text()
        self.path.write_text(content.replace('"c2":"32"', '"c2":"64"'))
        with patch("src.server.receipts.sign_receipt") as signer:
            with self.assertRaises(ChainIntegrityError):
                issue_receipt(self.board, voter_id="v1", server_private_key=self.server_key)
            signer.assert_not_called()


if __name__ == "__main__":
    unittest.main()
