"""Assinaturas e autenticação da #7, incluindo integração real com o cadastro.

Os pares cifrados pequenos são dados sintéticos para testar a assinatura:
não demonstram validade ElGamal, prova de bit, apuração ou segurança da eleição.
"""

import base64
from copy import deepcopy
import json
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from src.crypto.ballots import (
    BALLOT_DOMAIN,
    MAX_CANDIDATES,
    MAX_CIPHERTEXT_DIGITS,
    MAX_JSON_BYTES,
    BallotError,
    BallotFormatError,
    IneligibleVoterError,
    InvalidBallotSignatureError,
    canonical_ballot_bytes,
    load_signed_ballot,
    sign_ballot,
    verify_signed_ballot,
)
from src.crypto.keys import PublicKeyError, public_key_to_pem
from src.crypto.signatures import generate_signing_key, sign_bytes, verify_bytes
from src.server.registration import Registration
from tests.test_registration import P, Q


class SignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = generate_signing_key(2048)
        cls.public_pem = public_key_to_pem(cls.private_key.public_key())

    def test_generation_default_and_registration_policy(self):
        key = generate_signing_key()
        self.assertEqual(key.key_size, 3072)
        self.assertEqual(key.public_key().public_numbers().e, 65537)
        self.assertTrue(public_key_to_pem(key.public_key()).startswith("-----BEGIN PUBLIC KEY-----"))

    def test_reject_invalid_generation_sizes(self):
        for size in (1024, 0, True, "2048", 2048.0, 65536):
            with self.subTest(size=size), self.assertRaises(ValueError):
                generate_signing_key(size)

    def test_sign_and_verify(self):
        signature = sign_bytes(b"mensagem", self.private_key)
        self.assertTrue(verify_bytes(b"mensagem", signature, self.public_pem))
        # Um verificador da biblioteca, configurado explicitamente, também aceita.
        self.private_key.public_key().verify(
            signature, b"mensagem",
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )

    def test_reject_changed_message_or_signature(self):
        signature = sign_bytes(b"mensagem", self.private_key)
        self.assertFalse(verify_bytes(b"outra mensagem", signature, self.public_pem))
        changed = bytes([signature[0] ^ 1]) + signature[1:]
        self.assertFalse(verify_bytes(b"mensagem", changed, self.public_pem))
        self.assertFalse(verify_bytes(b"mensagem", b"", self.public_pem))

    def test_randomized_pss_signatures_are_both_valid(self):
        first = sign_bytes(b"mesma mensagem", self.private_key)
        second = sign_bytes(b"mesma mensagem", self.private_key)
        self.assertNotEqual(first, second)
        self.assertTrue(verify_bytes(b"mesma mensagem", first, self.public_pem))
        self.assertTrue(verify_bytes(b"mesma mensagem", second, self.public_pem))

    def test_wrong_public_key(self):
        other = public_key_to_pem(generate_signing_key(2048).public_key())
        self.assertFalse(verify_bytes(b"msg", sign_bytes(b"msg", self.private_key), other))

    def test_wrong_types_and_invalid_public_key(self):
        with self.assertRaises(TypeError):
            sign_bytes("texto", self.private_key)
        with self.assertRaises(TypeError):
            sign_bytes(b"msg", self.private_key.public_key())
        with self.assertRaises(TypeError):
            verify_bytes(b"msg", "assinatura", self.public_pem)
        with self.assertRaises(PublicKeyError):
            verify_bytes(b"msg", b"assinatura", "nao e PEM")

    def test_signing_rejects_small_private_key(self):
        small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        with self.assertRaises(PublicKeyError):
            sign_bytes(b"msg", small)

    def test_algorithm_and_salt_downgrade_are_rejected(self):
        configurations = (
            (padding.PKCS1v15(), hashes.SHA256()),
            (padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=0), hashes.SHA256()),
            (padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=32), hashes.SHA512()),
        )
        for scheme, digest in configurations:
            with self.subTest(scheme=type(scheme).__name__, digest=digest.name):
                signature = self.private_key.sign(b"msg", scheme, digest)
                self.assertFalse(verify_bytes(b"msg", signature, self.public_pem))


class BallotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = generate_signing_key(2048)
        cls.public_pem = public_key_to_pem(cls.private_key.public_key())
        cls.attacker_key = generate_signing_key(2048)

    def setUp(self):
        self.ballot = {
            "schema_version": 1,
            "election_id": "eleicao_2026",
            "voter_id": "eleitor_001",
            "ciphertexts": [
                {"candidate_id": "A", "c1": "4", "c2": "8"},
                {"candidate_id": "B", "c1": "16", "c2": "32"},
            ],
        }
        self.context = {
            "election_id": "eleicao_2026",
            "candidate_ids": ["A", "B"],
            "voter_public_keys": {"eleitor_001": self.public_pem},
        }

    def test_canonical_known_bytes(self):
        expected = (
            b'{"ciphertexts":[{"c1":"4","c2":"8","candidate_id":"A"},'
            b'{"c1":"16","c2":"32","candidate_id":"B"}],'
            b'"election_id":"eleicao_2026","schema_version":1,"voter_id":"eleitor_001"}'
        )
        self.assertEqual(canonical_ballot_bytes(self.ballot), expected)

    def test_field_order_and_json_whitespace_do_not_change_message(self):
        signed = sign_ballot(self.ballot, self.private_key)
        reordered = dict(reversed(list(self.ballot.items())))
        reordered["ciphertexts"] = [dict(reversed(list(c.items()))) for c in self.ballot["ciphertexts"]]
        signed["ballot"] = reordered
        parsed = load_signed_ballot(json.dumps(signed, indent=4).encode("utf-8"))
        self.assertEqual(verify_signed_ballot(parsed, **self.context), self.ballot)

    def test_sign_and_verify_round_trip(self):
        envelope = sign_ballot(self.ballot, self.private_key)
        loaded = load_signed_ballot(json.dumps(envelope))
        self.assertEqual(verify_signed_ballot(loaded, **self.context), self.ballot)

    def test_largest_supported_ballot_fits_json_reader(self):
        # Limites do assinador e leitor precisam ser compatíveis. Estes valores
        # continuam sintéticos: assinatura não atesta pertencimento ao grupo.
        candidates = [f"candidato_{index}" for index in range(MAX_CANDIDATES)]
        self.ballot["ciphertexts"] = [
            {"candidate_id": candidate, "c1": "9" * MAX_CIPHERTEXT_DIGITS,
             "c2": "9" * MAX_CIPHERTEXT_DIGITS}
            for candidate in candidates
        ]
        envelope = sign_ballot(self.ballot, self.private_key)
        encoded = json.dumps(envelope).encode("ascii")
        self.assertLessEqual(len(encoded), MAX_JSON_BYTES)
        parsed = load_signed_ballot(encoded)
        self.context["candidate_ids"] = candidates
        self.assertEqual(verify_signed_ballot(parsed, **self.context), self.ballot)

    def test_every_cipher_component_is_signed(self):
        original = sign_ballot(self.ballot, self.private_key)
        for index in (0, 1):
            for component in ("c1", "c2"):
                with self.subTest(index=index, component=component):
                    changed = deepcopy(original)
                    changed["ballot"]["ciphertexts"][index][component] = "64"
                    with self.assertRaises(InvalidBallotSignatureError):
                        verify_signed_ballot(changed, **self.context)

    def test_voter_id_is_signed_even_if_both_ids_have_same_public_key(self):
        envelope = sign_ballot(self.ballot, self.private_key)
        envelope["ballot"]["voter_id"] = "eleitor_002"
        self.context["voter_public_keys"]["eleitor_002"] = self.public_pem
        with self.assertRaises(InvalidBallotSignatureError):
            verify_signed_ballot(envelope, **self.context)

    def test_election_id_is_signed(self):
        envelope = sign_ballot(self.ballot, self.private_key)
        envelope["ballot"]["election_id"] = "eleicao_2027"
        self.context["election_id"] = "eleicao_2027"
        with self.assertRaises(InvalidBallotSignatureError):
            verify_signed_ballot(envelope, **self.context)

    def test_valid_ballot_from_other_election_is_rejected(self):
        envelope = sign_ballot(self.ballot, self.private_key)
        self.context["election_id"] = "eleicao_2027"
        with self.assertRaisesRegex(BallotError, "outra eleição"):
            verify_signed_ballot(envelope, **self.context)

    def test_candidate_id_is_signed(self):
        envelope = sign_ballot(self.ballot, self.private_key)
        envelope["ballot"]["ciphertexts"][0]["candidate_id"] = "C"
        self.context["candidate_ids"] = ["C", "B"]
        with self.assertRaises(InvalidBallotSignatureError):
            verify_signed_ballot(envelope, **self.context)

    def test_ciphertext_order_is_signed(self):
        envelope = sign_ballot(self.ballot, self.private_key)
        envelope["ballot"]["ciphertexts"].reverse()
        self.context["candidate_ids"] = ["B", "A"]
        with self.assertRaises(InvalidBallotSignatureError):
            verify_signed_ballot(envelope, **self.context)

    def test_candidate_context_is_checked_even_for_valid_signature(self):
        envelope = sign_ballot(self.ballot, self.private_key)
        for candidates in (["B", "A"], ["A", "C"], ["A", "B", "C"]):
            with self.subTest(candidates=candidates), self.assertRaises(BallotError):
                verify_signed_ballot(envelope, **{**self.context, "candidate_ids": candidates})

    def test_unknown_voter_is_rejected_even_with_valid_signature(self):
        envelope = sign_ballot(self.ballot, self.private_key)
        self.context["voter_public_keys"] = {}
        with self.assertRaises(IneligibleVoterError):
            verify_signed_ballot(envelope, **self.context)

    def test_attacker_cannot_sign_as_registered_voter(self):
        forged = sign_ballot(self.ballot, self.attacker_key)
        with self.assertRaises(InvalidBallotSignatureError):
            verify_signed_ballot(forged, **self.context)

    def test_envelope_cannot_supply_its_own_key_or_algorithm(self):
        for field, value in (("public_key", public_key_to_pem(self.attacker_key.public_key())),
                             ("algorithm", "none")):
            with self.subTest(field=field):
                envelope = sign_ballot(self.ballot, self.attacker_key)
                envelope[field] = value
                with self.assertRaises(BallotFormatError):
                    verify_signed_ballot(envelope, **self.context)

    def test_signature_from_another_domain_is_rejected(self):
        envelope = sign_ballot(self.ballot, self.private_key)
        for domain in (b"", b"URNA_ONLINE:RECEIPT:v1\x00"):
            with self.subTest(domain=domain):
                signature = sign_bytes(domain + canonical_ballot_bytes(self.ballot), self.private_key)
                envelope["signature"] = base64.b64encode(signature).decode("ascii")
                with self.assertRaises(InvalidBallotSignatureError):
                    verify_signed_ballot(envelope, **self.context)

    def test_independent_library_signature_is_accepted(self):
        message = BALLOT_DOMAIN + canonical_ballot_bytes(self.ballot)
        signature = self.private_key.sign(
            message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256()
        )
        envelope = {"ballot": self.ballot, "signature": base64.b64encode(signature).decode("ascii")}
        self.assertEqual(verify_signed_ballot(envelope, **self.context), self.ballot)

    def test_malformed_signatures_are_rejected(self):
        original = sign_ballot(self.ballot, self.private_key)
        for signature in ("", None, "%%%", "é", "A" * 1369, original["signature"] + "\n"):
            with self.subTest(signature_type=type(signature).__name__):
                with self.assertRaises(BallotFormatError):
                    verify_signed_ballot({**original, "signature": signature}, **self.context)
        with self.assertRaises(InvalidBallotSignatureError):
            verify_signed_ballot({**original, "signature": "YQ=="}, **self.context)

    def test_schema_version_missing_and_extra_fields(self):
        for field in self.ballot:
            with self.subTest(missing=field):
                changed = deepcopy(self.ballot)
                del changed[field]
                with self.assertRaises(BallotFormatError):
                    sign_ballot(changed, self.private_key)
        for version in (True, 1.0, "1", 2):
            with self.subTest(version=version), self.assertRaises(BallotFormatError):
                canonical_ballot_bytes({**self.ballot, "schema_version": version})
        for field in ("chosen_candidate", "randomness", "proofs", "timestamp"):
            with self.subTest(extra=field), self.assertRaises(BallotFormatError):
                canonical_ballot_bytes({**self.ballot, field: "extra"})

    def test_invalid_identifiers_and_decimal_components(self):
        for bad_id in ("", "José", " a", "a\n", 7, "a" * 65):
            for field in ("election_id", "voter_id"):
                with self.subTest(field=field, bad_id=bad_id), self.assertRaises(BallotFormatError):
                    canonical_ballot_bytes({**self.ballot, field: bad_id})
        for component in (0, 1, True, 1.5, "0", "01", "-1", "+1", " 1", "1e3", "١", "9" * 2501):
            changed = deepcopy(self.ballot)
            changed["ciphertexts"][0]["c1"] = component
            with self.subTest(component_type=type(component).__name__), self.assertRaises(BallotFormatError):
                canonical_ballot_bytes(changed)

    def test_duplicate_missing_and_extra_ciphertext_fields(self):
        changed = deepcopy(self.ballot)
        changed["ciphertexts"][1]["candidate_id"] = "A"
        with self.assertRaises(BallotFormatError):
            canonical_ballot_bytes(changed)
        for ciphertexts in ([], self.ballot["ciphertexts"][:1], {}, [None, None], self.ballot["ciphertexts"] * 129):
            with self.subTest(kind=type(ciphertexts).__name__), self.assertRaises(BallotFormatError):
                canonical_ballot_bytes({**self.ballot, "ciphertexts": ciphertexts})
        for field in ("candidate_id", "c1", "c2"):
            changed = deepcopy(self.ballot)
            del changed["ciphertexts"][0][field]
            with self.subTest(missing=field), self.assertRaises(BallotFormatError):
                canonical_ballot_bytes(changed)
        changed = deepcopy(self.ballot)
        changed["ciphertexts"][0]["r"] = "segredo"
        with self.assertRaises(BallotFormatError):
            canonical_ballot_bytes(changed)

    def test_json_duplicate_keys_are_rejected_at_all_levels(self):
        document = json.dumps(sign_ballot(self.ballot, self.private_key))
        variants = (
            document.replace('"ballot":', '"ballot": {}, "ballot":', 1),
            document.replace('"voter_id":', '"voter_id": "outro", "voter_id":', 1),
            document.replace('"c1":', '"c1": "999", "c1":', 1),
        )
        for variant in variants:
            with self.subTest(variant=variant[:40]), self.assertRaises(BallotFormatError):
                load_signed_ballot(variant)

    def test_invalid_json_constants_encoding_size_and_depth(self):
        document = json.dumps(sign_ballot(self.ballot, self.private_key))
        variants = (
            document.replace('"schema_version": 1', '"schema_version": NaN'),
            document.replace('"schema_version": 1', '"schema_version": Infinity'),
            b"\xff", "{", "[]", "null", " " * (MAX_JSON_BYTES + 1),
            "[" * 2000 + "]" * 2000, None,
        )
        for variant in variants:
            with self.subTest(kind=type(variant).__name__), self.assertRaises(BallotFormatError):
                load_signed_ballot(variant)

    def test_bad_trusted_context_fails_closed(self):
        envelope = sign_ballot(self.ballot, self.private_key)
        for candidate_ids in ("AB", ["A"], ["A", "A"], ["A", None]):
            with self.subTest(candidate_ids=candidate_ids), self.assertRaises(BallotFormatError):
                verify_signed_ballot(envelope, **{**self.context, "candidate_ids": candidate_ids})
        with self.assertRaises(PublicKeyError):
            verify_signed_ballot(envelope, **{**self.context, "voter_public_keys": {"eleitor_001": "bad"}})

    def test_signing_and_verification_return_independent_copies(self):
        envelope = sign_ballot(self.ballot, self.private_key)
        self.ballot["ciphertexts"][0]["c1"] = "999"
        self.assertEqual(envelope["ballot"]["ciphertexts"][0]["c1"], "4")
        verified = verify_signed_ballot(envelope, **self.context)
        verified["ciphertexts"][0]["c1"] = "777"
        self.assertEqual(envelope["ballot"]["ciphertexts"][0]["c1"], "4")

    def test_integration_with_registration_public_export(self):
        registry = Registration("eleicao_2026", p=P, q=Q, state_provider=lambda: "CADASTRO")
        registry.register_voter("eleitor_001", self.public_pem)
        registry.freeze()
        public_data = registry.export_public_data()
        context = {
            "election_id": public_data["election_id"],
            "candidate_ids": ["A", "B"],
            "voter_public_keys": {v["voter_id"]: v["public_key_pem"] for v in public_data["voters"]},
        }
        # Só os dados públicos chegam ao verificador; ele não recebe registry.
        envelope = sign_ballot(self.ballot, self.private_key)
        self.assertEqual(verify_signed_ballot(envelope, **context), self.ballot)


if __name__ == "__main__":
    unittest.main()
