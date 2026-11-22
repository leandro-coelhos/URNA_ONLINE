"""Contrato da #8: publicação, leitura pública e ataques ao histórico.

Usamos chaves RSA reais e cifras sintéticas. Estes testes não demonstram
validade ElGamal ou uma eleição completa. Arquivos ficam em diretórios
temporários, removidos pelo próprio TemporaryDirectory ao terminar.
"""

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from src.bulletin_board.board import BulletinBoard
from src.bulletin_board.hash_chain import (
    MAX_RECORD_BYTES, BoardFormatError, ChainIntegrityError, DuplicateVoteError,
    genesis_hash, hash_record, make_checkpoint, make_record,
    read_records, verify_board,
)
from src.crypto.ballots import (
    MAX_CANDIDATES, MAX_CIPHERTEXT_DIGITS, BallotError,
    IneligibleVoterError, InvalidBallotSignatureError, sign_ballot,
)
from src.crypto.keys import PublicKeyError, public_key_to_pem
from src.crypto.signatures import generate_signing_key
from src.server.registration import Registration
from tests.test_registration import P, Q


class BulletinBoardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = {f"eleitor_{i}": generate_signing_key(2048) for i in range(1, 5)}
        cls.public_keys = {v: public_key_to_pem(k.public_key()) for v, k in cls.keys.items()}

    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "bulletin_board.jsonl"
        self.context = {
            "election_id": "eleicao_2026", "candidate_ids": ["A", "B"],
            "voter_public_keys": dict(self.public_keys),
        }
        self.envelopes = {}
        for voter_id, key in self.keys.items():
            ballot = {
                "schema_version": 1, "election_id": "eleicao_2026", "voter_id": voter_id,
                "ciphertexts": [
                    {"candidate_id": "A", "c1": "4", "c2": "8"},
                    {"candidate_id": "B", "c1": "16", "c2": "32"},
                ],
            }
            self.envelopes[voter_id] = sign_ballot(ballot, key)
        self.board = BulletinBoard.create(self.path, **self.context)

    def populate(self):
        return [self.board.append(self.envelopes[f"eleitor_{i}"]) for i in range(1, 4)]

    def verify(self, records, checkpoint=None):
        return verify_board(
            records, **self.context,
            expected_checkpoint=self.board.checkpoint if checkpoint is None else checkpoint,
        )

    def rechain(self, records):
        # Simula o administrador: SHA-256 é público, então ele pode recalcular
        # TODOS os elos sem conhecer nenhuma chave privada de eleitor.
        previous = genesis_hash(self.context["election_id"])
        result = []
        for index, record in enumerate(records):
            new = make_record(
                {"ballot": record["ballot"], "signature": record["signature"]},
                index=index, previous_hash=previous,
            )
            result.append(new)
            previous = new["hash"]
        return result

    def checkpoint_for(self, records):
        return make_checkpoint(
            election_id=self.context["election_id"], size=len(records),
            head_hash=records[-1]["hash"] if records else genesis_hash(self.context["election_id"]),
        )

    def test_empty_board_and_defined_genesis(self):
        expected = hashlib.sha256(b"URNA_ONLINE:BOARD:GENESIS:v1\x00eleicao_2026").hexdigest()
        self.assertEqual(genesis_hash("eleicao_2026"), expected)
        self.assertNotEqual(expected, genesis_hash("outra_eleicao"))
        self.assertEqual(self.path.read_bytes(), b"")
        self.assertEqual(self.board.records(), [])
        self.assertEqual(self.board.checkpoint["head_hash"], expected)
        self.assertEqual(self.verify([])["size"], 0)

    def test_canonical_hash_against_explicit_bytes(self):
        # A assinatura fictícia serve APENAS para testar o formato do hash.
        body = {
            "schema_version": 1, "index": 0, "previous_hash": "0" * 64,
            "ballot": {"schema_version": 1, "election_id": "e", "voter_id": "v", "ciphertexts": [
                {"candidate_id": "A", "c1": "4", "c2": "8"},
                {"candidate_id": "B", "c1": "16", "c2": "32"},
            ]}, "signature": "AA==",
        }
        canonical = (
            b'{"ballot":{"ciphertexts":[{"c1":"4","c2":"8","candidate_id":"A"},'
            b'{"c1":"16","c2":"32","candidate_id":"B"}],"election_id":"e",'
            b'"schema_version":1,"voter_id":"v"},"index":0,"previous_hash":"'
            + b"0" * 64 + b'","schema_version":1,"signature":"AA=="}'
        )
        expected = hashlib.sha256(b"URNA_ONLINE:BOARD:RECORD:v1\x00" + canonical).hexdigest()
        self.assertEqual(hash_record(body), expected)
        self.assertEqual(hash_record(dict(reversed(list(body.items())))), expected)

    def test_three_ballots_are_persisted_and_publicly_verified(self):
        records = self.populate()
        self.assertEqual(self.board.records(), records)
        self.assertEqual([r["index"] for r in records], [0, 1, 2])
        self.assertEqual(records[0]["previous_hash"], genesis_hash("eleicao_2026"))
        for previous, current in zip(records, records[1:]):
            self.assertEqual(current["previous_hash"], previous["hash"])
        self.assertEqual(self.path.read_bytes().count(b"\n"), 3)
        with self.path.open("rb") as stream:
            self.assertEqual(self.verify(read_records(stream))["size"], 3)

    def test_append_preserves_previous_file_bytes(self):
        self.board.append(self.envelopes["eleitor_1"])
        prefix = self.path.read_bytes()
        self.board.append(self.envelopes["eleitor_2"])
        self.assertTrue(self.path.read_bytes().startswith(prefix))
        self.assertGreater(self.path.stat().st_size, len(prefix))

    def test_duplicate_vote_rejected_without_writing(self):
        self.board.append(self.envelopes["eleitor_1"])
        before = self.path.read_bytes(), self.board.checkpoint
        # Outra assinatura PSS da mesma cédula continua sendo voto duplicado.
        again = sign_ballot(self.envelopes["eleitor_1"]["ballot"], self.keys["eleitor_1"])
        with self.assertRaises(DuplicateVoteError):
            self.board.append(again)
        self.assertEqual((self.path.read_bytes(), self.board.checkpoint), before)

    def test_ineligible_voter_rejected_without_writing(self):
        ballot = deepcopy(self.envelopes["eleitor_1"]["ballot"])
        ballot["voter_id"] = "nao_cadastrado"
        with self.assertRaises(IneligibleVoterError):
            self.board.append(sign_ballot(ballot, self.keys["eleitor_1"]))
        self.assertEqual(self.path.read_bytes(), b"")

    def test_invalid_signature_rejected_without_writing(self):
        envelope = deepcopy(self.envelopes["eleitor_1"])
        envelope["ballot"]["ciphertexts"][0]["c2"] = "99"
        with self.assertRaises(InvalidBallotSignatureError):
            self.board.append(envelope)
        self.assertEqual(self.path.read_bytes(), b"")

    def test_wrong_election_or_candidate_order_rejected(self):
        for change in ("election", "candidates"):
            ballot = deepcopy(self.envelopes["eleitor_1"]["ballot"])
            if change == "election":
                ballot["election_id"] = "outra"
            else:
                ballot["ciphertexts"].reverse()
            with self.subTest(change=change), self.assertRaises(BallotError):
                self.board.append(sign_ballot(ballot, self.keys["eleitor_1"]))
        self.assertEqual(self.board.checkpoint["size"], 0)

    def test_records_envelopes_and_checkpoints_are_independent_copies(self):
        envelope = deepcopy(self.envelopes["eleitor_1"])
        record = self.board.append(envelope)
        before = self.path.read_bytes()
        envelope["ballot"]["voter_id"] = "alterado"
        record["ballot"]["voter_id"] = "alterado"
        self.board.records()[0]["ballot"]["voter_id"] = "alterado"
        self.board.checkpoint["size"] = 999
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.board.checkpoint["size"], 1)
        self.assertEqual(self.board.records()[0]["ballot"]["voter_id"], "eleitor_1")

    def test_context_is_copied_at_creation(self):
        self.context["candidate_ids"].reverse()
        self.context["voter_public_keys"].clear()
        self.board.append(self.envelopes["eleitor_1"])
        self.assertEqual(self.board.checkpoint["size"], 1)

    def test_changed_ciphertext_and_signature_break_hash(self):
        records = self.populate()
        for field in ("ciphertext", "signature"):
            altered = deepcopy(records)
            if field == "ciphertext":
                altered[0]["ballot"]["ciphertexts"][0]["c2"] = "99"
            else:
                altered[0]["signature"] = self.envelopes["eleitor_4"]["signature"]
            with self.subTest(field=field), self.assertRaises(ChainIntegrityError):
                self.verify(altered)

    def test_first_middle_last_and_all_removals_detected(self):
        records = self.populate()
        variants = [records[1:], records[:1] + records[2:], records[:-1], []]
        for index, variant in enumerate(variants):
            with self.subTest(variant=index), self.assertRaises(ChainIntegrityError):
                self.verify(variant)

    def test_reordering_detected(self):
        records = self.populate()
        with self.assertRaises(ChainIntegrityError):
            self.verify([records[1], records[0], records[2]])

    def test_changed_index_and_previous_hash_detected_even_after_rehashing(self):
        records = self.populate()
        for field, value in (("index", 10), ("previous_hash", "0" * 64)):
            altered = deepcopy(records)
            altered[1][field] = value
            altered[1]["hash"] = hash_record({k: v for k, v in altered[1].items() if k != "hash"})
            with self.subTest(field=field), self.assertRaises(ChainIntegrityError):
                self.verify(altered)

    def test_removal_and_reordering_with_recomputed_chain_detected_by_checkpoint(self):
        records = self.populate()
        for variant in (records[1:], records[:1] + records[2:], list(reversed(records))):
            altered = self.rechain(variant)
            with self.subTest(size=len(variant)), self.assertRaises(ChainIntegrityError):
                self.verify(altered)

    def test_extra_valid_signed_vote_detected_by_original_checkpoint(self):
        records = self.populate()
        extra = make_record(self.envelopes["eleitor_4"], index=3, previous_hash=records[-1]["hash"])
        for altered in (records + [extra], self.rechain([extra] + records)):
            with self.subTest(first=altered[0]["ballot"]["voter_id"]), self.assertRaises(ChainIntegrityError):
                self.verify(altered)

    def test_recomputed_hashes_do_not_hide_invalid_signature(self):
        records = self.populate()
        records[0]["ballot"]["ciphertexts"][0]["c2"] = "99"
        altered = self.rechain(records)
        with self.assertRaises(InvalidBallotSignatureError):
            self.verify(altered, self.checkpoint_for(altered))

    def test_recomputed_hashes_do_not_hide_ineligible_voter(self):
        ballot = deepcopy(self.envelopes["eleitor_1"]["ballot"])
        ballot["voter_id"] = "intruso"
        record = make_record(
            sign_ballot(ballot, self.keys["eleitor_1"]), index=0, previous_hash=genesis_hash("eleicao_2026")
        )
        with self.assertRaises(IneligibleVoterError):
            self.verify([record], self.checkpoint_for([record]))

    def test_duplicate_detected_even_with_consistent_chain_and_checkpoint(self):
        records = self.populate()
        altered = self.rechain(records + [records[0]])
        with self.assertRaises(DuplicateVoteError):
            self.verify(altered, self.checkpoint_for(altered))

    def test_untrusted_checkpoint_cannot_protect_history(self):
        # Limitação demonstrada, não uma garantia: se o auditor aceitar TAMBÉM
        # o checkpoint adulterado, uma remoção com novos elos parece consistente.
        altered = self.rechain(self.populate()[1:])
        attacker_checkpoint = self.checkpoint_for(altered)
        self.assertEqual(self.verify(altered, attacker_checkpoint)["size"], 2)
        with self.assertRaises(ChainIntegrityError):
            self.verify(altered)

    def test_checkpoint_required_and_exact_snapshot_only(self):
        self.populate()
        with self.assertRaises(TypeError):
            verify_board(self.board.records(), **self.context)
        with self.assertRaises(BoardFormatError):
            verify_board(self.board.records(), **self.context, expected_checkpoint=None)
        old = self.board.checkpoint
        self.board.append(self.envelopes["eleitor_4"])
        with self.assertRaises(ChainIntegrityError):
            self.verify(self.board.records(), old)

    def test_malformed_checkpoint_rejected(self):
        checkpoint = self.board.checkpoint
        variants = [
            {**checkpoint, "extra": 1}, {**checkpoint, "schema_version": True},
            {**checkpoint, "size": True}, {**checkpoint, "size": -1},
            {**checkpoint, "size": 2**63}, {**checkpoint, "head_hash": "A" * 64},
        ]
        for altered in variants:
            with self.subTest(checkpoint=altered), self.assertRaises(BoardFormatError):
                self.verify([], altered)
        with self.assertRaises(ChainIntegrityError):
            self.verify([], {**checkpoint, "election_id": "outra"})
        with self.assertRaises(ChainIntegrityError):
            self.verify([], {**checkpoint, "head_hash": "0" * 64})

    def test_malformed_records_rejected(self):
        record = self.board.append(self.envelopes["eleitor_1"])
        variants = [
            {**record, "extra": 1}, {**record, "schema_version": True},
            {**record, "index": True}, {**record, "index": -1},
            {**record, "hash": "0" * 63}, {**record, "previous_hash": "F" * 64},
            {k: v for k, v in record.items() if k != "signature"}, [],
        ]
        for altered in variants:
            with self.subTest(record=altered), self.assertRaises(BoardFormatError):
                self.verify([altered])

    def test_ambiguous_or_malformed_jsonl_rejected(self):
        documents = [
            b'\n', b'{"index":0,"index":1}\n', b'{"ballot":{"voter_id":"a","voter_id":"b"}}\n',
            b'{"index":NaN}\n', b'{"index":Infinity}\n', b'\xff\n', b'{}',
            b'{}{}\n', b'[' * 2000 + b']' * 2000 + b'\n', b' ' * MAX_RECORD_BYTES + b'\n',
        ]
        for document in documents:
            with self.subTest(start=document[:40]), self.assertRaises(BoardFormatError):
                list(read_records(io.BytesIO(document)))

    def test_parser_alone_does_not_authenticate_records(self):
        self.assertEqual(list(read_records(io.BytesIO(b'{}\n'))), [{}])
        with self.assertRaises(BoardFormatError):
            self.verify(read_records(io.BytesIO(b'{}\n')))

    def test_json_spacing_and_object_order_do_not_change_hash(self):
        records = self.populate()
        document = b"".join(
            (json.dumps(dict(reversed(list(r.items())))) + "\n").encode("utf-8") for r in records
        )
        self.assertEqual(self.verify(read_records(io.BytesIO(document))), self.board.checkpoint)

    def test_reopen_preserves_history_and_duplicate_detection(self):
        records = self.populate()
        reopened = BulletinBoard(self.path, **self.context, expected_checkpoint=self.board.checkpoint)
        self.assertEqual(reopened.records(), records)
        with self.assertRaises(DuplicateVoteError):
            reopened.append(self.envelopes["eleitor_1"])
        reopened.append(self.envelopes["eleitor_4"])
        self.assertEqual(reopened.checkpoint["size"], 4)

    def test_create_does_not_overwrite_existing_file(self):
        self.populate()
        before = self.path.read_bytes()
        with self.assertRaises(FileExistsError):
            BulletinBoard.create(self.path, **self.context)
        self.assertEqual(self.path.read_bytes(), before)

    def test_missing_file_is_not_silently_recreated(self):
        missing = self.path.parent / "missing.jsonl"
        with self.assertRaises(FileNotFoundError):
            BulletinBoard(missing, **self.context, expected_checkpoint=self.board.checkpoint)
        self.assertFalse(missing.exists())

    def test_tampered_file_rejected_on_reopen_and_before_append(self):
        self.populate()
        self.path.write_bytes(self.path.read_bytes().split(b"\n", 1)[1])
        before = self.path.read_bytes()
        with self.assertRaises(ChainIntegrityError):
            BulletinBoard(self.path, **self.context, expected_checkpoint=self.board.checkpoint)
        with self.assertRaises(ChainIntegrityError):
            self.board.append(self.envelopes["eleitor_4"])
        self.assertEqual(self.path.read_bytes(), before)

    def test_truncated_final_line_is_rejected(self):
        self.populate()
        self.path.write_bytes(self.path.read_bytes()[:-1])
        with self.assertRaises(BoardFormatError):
            self.board.records()

    def test_two_instances_do_not_silently_fork_or_overwrite(self):
        other = BulletinBoard(self.path, **self.context, expected_checkpoint=self.board.checkpoint)
        self.board.append(self.envelopes["eleitor_1"])
        before = self.path.read_bytes()
        with self.assertRaises(ChainIntegrityError):
            other.append(self.envelopes["eleitor_2"])
        self.assertEqual(self.path.read_bytes(), before)

    def test_disk_sync_failure_does_not_report_success_or_advance_checkpoint(self):
        before = self.board.checkpoint
        with patch("src.bulletin_board.board.os.fsync", side_effect=OSError("falha simulada")):
            with self.assertRaises(OSError):
                self.board.append(self.envelopes["eleitor_1"])
        self.assertEqual(self.board.checkpoint, before)
        # A linha pode ter sido escrita apesar do erro: não fazemos rollback
        # destrutivo nem aceitamos continuar ignorando a situação ambígua.
        with self.assertRaises(ChainIntegrityError):
            self.board.append(self.envelopes["eleitor_2"])

    def test_invalid_context_rejected_before_creating_file(self):
        bad_contexts = [
            {**self.context, "election_id": " "}, {**self.context, "candidate_ids": "AB"},
            {**self.context, "candidate_ids": ["A"]}, {**self.context, "candidate_ids": ["A", "A"]},
            {**self.context, "voter_public_keys": []},
            {**self.context, "voter_public_keys": {"v": "invalid PEM"}},
            {**self.context, "voter_public_keys": {"v": self.public_keys["eleitor_1"], "w": self.public_keys["eleitor_1"]}},
        ]
        for index, context in enumerate(bad_contexts):
            path = self.path.parent / f"invalid_{index}.jsonl"
            with self.subTest(index=index), self.assertRaises((BoardFormatError, PublicKeyError)):
                BulletinBoard.create(path, **context)
            self.assertFalse(path.exists())

    def test_integration_with_frozen_registration_export(self):
        registration = Registration("eleicao_2026", p=P, q=Q, state_provider=lambda: "CADASTRO")
        for voter_id, pem in self.public_keys.items():
            registration.register_voter(voter_id, pem)
        registration.freeze()
        public = registration.export_public_data()
        context = {
            "election_id": public["election_id"], "candidate_ids": ["A", "B"],
            "voter_public_keys": {v["voter_id"]: v["public_key_pem"] for v in public["voters"]},
        }
        board = BulletinBoard.create(self.path.parent / "integrated.jsonl", **context)
        board.append(self.envelopes["eleitor_1"])
        self.assertEqual(verify_board(board.records(), **context, expected_checkpoint=board.checkpoint)["size"], 1)

    def test_largest_ballot_fits_jsonl_reader_limit(self):
        context = {**self.context, "candidate_ids": [f"c{i}" for i in range(MAX_CANDIDATES)]}
        ballot = deepcopy(self.envelopes["eleitor_1"]["ballot"])
        ballot["ciphertexts"] = [
            {"candidate_id": candidate, "c1": "9" * MAX_CIPHERTEXT_DIGITS, "c2": "9" * MAX_CIPHERTEXT_DIGITS}
            for candidate in context["candidate_ids"]
        ]
        path = self.path.parent / "large.jsonl"
        board = BulletinBoard.create(path, **context)
        board.append(sign_ballot(ballot, self.keys["eleitor_1"]))
        self.assertLessEqual(path.stat().st_size, MAX_RECORD_BYTES)
        self.assertEqual(board.records()[0]["ballot"], ballot)


if __name__ == "__main__":
    unittest.main()
