"""Testes da issue #4: chaves reais RSA e grupo padronizado de 2048 bits.

As chaves privadas RSA são temporárias e nunca são gravadas. Os expoentes
pequenos das autoridades são exemplos de teste, não geração segura de chaves.
"""

from dataclasses import FrozenInstanceError
import json
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from src.server.registration import (
    DuplicateParticipantError,
    InvalidIdentifierError,
    InvalidPublicKeyError,
    Registration,
    RegistrationClosedError,
)


# RFC 3526, seção 3, grupo 14. Esta constante pertence APENAS à fixture de
# testes: a eleição real obterá parâmetros validados de src/crypto/group.py.
# Fonte: https://www.rfc-editor.org/rfc/rfc3526#section-3
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
Q = (P - 1) // 2


def public_pem(key, fmt=serialization.PublicFormat.SubjectPublicKeyInfo):
    """Obtém apenas a parte pública para entregar ao cadastro."""
    return key.public_key().public_bytes(serialization.Encoding.PEM, fmt)


class RegistrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Gerar uma vez por classe reduz o custo sem usar chaves versionadas.
        cls.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pem = public_pem(cls.rsa_key)
        cls.second_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.second_pem = public_pem(cls.second_key)

    def setUp(self):
        self.state = "CADASTRO"
        self.registration = Registration(
            "eleicao_2026", p=P, q=Q, state_provider=lambda: self.state
        )

    def test_register_and_query_voter(self):
        voter = self.registration.register_voter("eleitor_001", self.pem)
        self.assertEqual(voter.voter_id, "eleitor_001")
        self.assertEqual(voter.public_key_pem, self.pem.decode("ascii"))
        self.assertEqual(self.registration.get_voter("eleitor_001"), voter)

    def test_accept_text_pem(self):
        voter = self.registration.register_voter("eleitor_001", self.pem.decode("ascii"))
        self.assertEqual(voter.public_key_pem, self.pem.decode("ascii"))

    def test_register_three_authorities(self):
        for index in range(1, 4):
            h_i = pow(2, index + 10, P)
            authority = self.registration.register_authority(f"autoridade_{index}", h_i)
            self.assertEqual(authority.public_key, h_i)
            self.assertEqual(self.registration.get_authority(authority.authority_id), authority)
        self.assertEqual(len(self.registration.export_public_data()["authorities"]), 3)

    def test_duplicate_voter_id_does_not_replace_key(self):
        self.registration.register_voter("eleitor_001", self.pem)
        with self.assertRaises(DuplicateParticipantError):
            self.registration.register_voter("eleitor_001", self.second_pem)
        self.assertEqual(self.registration.get_voter("eleitor_001").public_key_pem,
                         self.pem.decode("ascii"))

    def test_same_rsa_key_in_another_format_is_still_duplicate(self):
        self.registration.register_voter("eleitor_001", self.pem)
        pkcs1 = public_pem(self.rsa_key, serialization.PublicFormat.PKCS1)
        with self.assertRaises(DuplicateParticipantError):
            self.registration.register_voter("eleitor_002", pkcs1)
        with self.assertRaises(DuplicateParticipantError):
            self.registration.register_voter("eleitor_002", self.pem.replace(b"\n", b"\r\n"))

    def test_duplicate_authority_id_and_key(self):
        self.registration.register_authority("autoridade_1", pow(2, 11, P))
        with self.assertRaises(DuplicateParticipantError):
            self.registration.register_authority("autoridade_1", pow(2, 12, P))
        with self.assertRaises(DuplicateParticipantError):
            self.registration.register_authority("autoridade_2", pow(2, 11, P))
        self.assertEqual(self.registration.get_authority("autoridade_1").public_key,
                         pow(2, 11, P))

    def test_participant_can_be_both_voter_and_authority(self):
        self.registration.register_voter("pessoa_1", self.pem)
        self.registration.register_authority("pessoa_1", pow(2, 11, P))
        self.assertEqual(self.registration.get_voter("pessoa_1").voter_id, "pessoa_1")
        self.assertEqual(self.registration.get_authority("pessoa_1").authority_id, "pessoa_1")

    def test_reject_invalid_identifiers_without_changing_registry(self):
        for identifier in ("", " ", " eleitor", "eleitor ", "../id", "a\nb", "josé", "a" * 65, 1, None):
            with self.subTest(identifier=identifier):
                with self.assertRaises(InvalidIdentifierError):
                    self.registration.register_voter(identifier, self.pem)
                with self.assertRaises(InvalidIdentifierError):
                    self.registration.register_authority(identifier, pow(2, 11, P))
        self.assertEqual(self.registration.export_public_data()["voters"], [])
        self.assertEqual(self.registration.export_public_data()["authorities"], [])

    def test_reject_malformed_or_ambiguous_pem(self):
        invalid_keys = (
            b"not a key", "ç", b"", 42, None, b"a" * 16_385,
            self.pem + self.second_pem, self.pem + b"extra bytes",
            b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
        )
        for key in invalid_keys:
            with self.subTest(key_type=type(key).__name__):
                with self.assertRaises(InvalidPublicKeyError):
                    self.registration.register_voter("eleitor_001", key)
        self.assertEqual(self.registration.export_public_data()["voters"], [])

    def test_reject_private_key(self):
        private_pem = self.rsa_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with self.assertRaises(InvalidPublicKeyError):
            self.registration.register_voter("eleitor_001", private_pem)

    def test_reject_non_rsa_key(self):
        with self.assertRaises(InvalidPublicKeyError):
            self.registration.register_voter("eleitor_001", public_pem(ed25519.Ed25519PrivateKey.generate()))

    def test_reject_small_rsa_key(self):
        small_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        with self.assertRaises(InvalidPublicKeyError):
            self.registration.register_voter("eleitor_001", public_pem(small_key))

    def test_reject_rsa_exponent_outside_policy(self):
        legacy_key = rsa.generate_private_key(public_exponent=3, key_size=2048)
        with self.assertRaises(InvalidPublicKeyError):
            self.registration.register_voter("eleitor_001", public_pem(legacy_key))

    def test_reject_even_rsa_modulus(self):
        numbers = self.rsa_key.public_key().public_numbers()
        invalid_key = rsa.RSAPublicNumbers(65537, numbers.n - 1).public_key()
        invalid_pem = invalid_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with self.assertRaises(InvalidPublicKeyError):
            self.registration.register_voter("eleitor_001", invalid_pem)

    def test_reject_invalid_authority_keys_including_non_subgroup_member(self):
        # P-4 está no intervalo aceito, mas não no subgrupo de ordem Q.
        self.assertNotEqual(pow(P - 4, Q, P), 1)
        for key in (-1, 0, 1, P - 1, P, P + 4, P - 4, True, "2048", 2.0, None):
            with self.subTest(key=key):
                with self.assertRaises(InvalidPublicKeyError):
                    self.registration.register_authority("autoridade_1", key)
        self.assertEqual(self.registration.export_public_data()["authorities"], [])

    def test_reject_registration_outside_registration_phase(self):
        for state in ("CONFIGURACAO", "VOTACAO_ABERTA", "ENCERRADA", "APURACAO", "AUDITADA", "INVALIDO", None):
            with self.subTest(state=state):
                registration = Registration("eleicao_2026", p=P, q=Q, state_provider=lambda: state)
                with self.assertRaises(RegistrationClosedError):
                    registration.register_voter("eleitor_001", self.pem)
                with self.assertRaises(RegistrationClosedError):
                    registration.register_authority("autoridade_1", pow(2, 11, P))

    def test_state_provider_is_consulted_again(self):
        self.registration.register_voter("eleitor_001", self.pem)
        self.state = "VOTACAO_ABERTA"
        with self.assertRaises(RegistrationClosedError):
            self.registration.register_voter("eleitor_002", self.second_pem)
        self.state = "CADASTRO"
        with self.assertRaises(RegistrationClosedError):
            self.registration.register_authority("autoridade_1", pow(2, 11, P))

    def test_registration_phase_can_start_after_configuration(self):
        # Recusar uma tentativa antecipada não deve impedir o cadastro quando
        # o controlador avançar legitimamente de CONFIGURACAO para CADASTRO.
        self.state = "CONFIGURACAO"
        with self.assertRaises(RegistrationClosedError):
            self.registration.register_voter("eleitor_001", self.pem)
        with self.assertRaises(RegistrationClosedError):
            self.registration.register_authority("autoridade_1", pow(2, 11, P))

        self.state = "CADASTRO"
        self.registration.register_voter("eleitor_001", self.pem)
        self.registration.register_authority("autoridade_1", pow(2, 11, P))
        self.assertEqual(self.registration.get_voter("eleitor_001").voter_id, "eleitor_001")
        self.assertEqual(self.registration.get_authority("autoridade_1").public_key,
                         pow(2, 11, P))

    def test_state_provider_failure_does_not_register_participant(self):
        # Se o controlador não conseguir informar a etapa, nenhuma inscrição
        # pode ser aceita como se a eleição estivesse em CADASTRO.
        def unavailable_state():
            raise RuntimeError("Estado da eleição indisponível.")

        registration = Registration(
            "eleicao_2026", p=P, q=Q, state_provider=unavailable_state
        )
        before = registration.export_public_data()
        with self.assertRaisesRegex(RuntimeError, "Estado da eleição indisponível"):
            registration.register_voter("eleitor_001", self.pem)
        with self.assertRaisesRegex(RuntimeError, "Estado da eleição indisponível"):
            registration.register_authority("autoridade_1", pow(2, 11, P))
        self.assertEqual(registration.export_public_data(), before)

    def test_complete_registration_flow(self):
        """Três eleitores e três autoridades: inscrição, fechamento e consultas.

        Este cenário exercita apenas o cadastro. A variável self.state faz o
        papel do futuro controlador, sem simular votação ou apuração completas.
        """
        third_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        voter_keys = (self.pem, self.second_pem, public_pem(third_key))
        for index, pem in enumerate(voter_keys, start=1):
            self.registration.register_voter(f"eleitor_{index:03}", pem)
            self.registration.register_authority(
                f"autoridade_{index}", pow(2, index + 10, P)
            )

        # Contrato da #5: congelar o cadastro antes de abrir a votação.
        self.registration.freeze()
        snapshot = self.registration.export_public_data()
        self.state = "VOTACAO_ABERTA"
        with self.assertRaises(RegistrationClosedError):
            self.registration.register_voter("eleitor_004", self.pem)
        with self.assertRaises(RegistrationClosedError):
            self.registration.register_authority("autoridade_4", pow(2, 14, P))

        self.state = "ENCERRADA"
        with self.assertRaises(RegistrationClosedError):
            self.registration.register_voter("eleitor_004", self.pem)
        with self.assertRaises(RegistrationClosedError):
            self.registration.register_authority("autoridade_4", pow(2, 14, P))

        # O congelamento preserva as consultas de que votação e auditoria
        # precisarão: impede novas inscrições sem apagar as existentes.
        self.assertEqual(len(snapshot["voters"]), 3)
        self.assertEqual(len(snapshot["authorities"]), 3)
        self.assertTrue(snapshot["frozen"])
        self.assertEqual(self.registration.export_public_data(), snapshot)
        for index, pem in enumerate(voter_keys, start=1):
            self.assertEqual(
                self.registration.get_voter(f"eleitor_{index:03}").public_key_pem,
                pem.decode("ascii"),
            )
            self.assertEqual(
                self.registration.get_authority(f"autoridade_{index}").public_key,
                pow(2, index + 10, P),
            )

    def test_freeze_is_irreversible_and_preserves_queries(self):
        self.registration.register_voter("eleitor_001", self.pem)
        self.registration.freeze()
        self.registration.freeze()
        with self.assertRaises(RegistrationClosedError):
            self.registration.register_voter("eleitor_002", self.second_pem)
        with self.assertRaises(RegistrationClosedError):
            self.registration.register_authority("autoridade_1", pow(2, 11, P))
        self.assertEqual(self.registration.get_voter("eleitor_001").voter_id, "eleitor_001")

    def test_unknown_participant(self):
        with self.assertRaises(KeyError):
            self.registration.get_voter("desconhecido")
        with self.assertRaises(KeyError):
            self.registration.get_authority("desconhecido")

    def test_export_contains_only_public_fields_and_is_an_independent_copy(self):
        voter = self.registration.register_voter("eleitor_001", self.pem)
        authority = self.registration.register_authority("autoridade_1", pow(2, 1234, P))
        self.registration.freeze()
        exported = json.loads(json.dumps(self.registration.export_public_data()))
        self.assertEqual(exported, {
            "schema_version": 1, "election_id": "eleicao_2026", "frozen": True,
            "voters": [{"voter_id": voter.voter_id, "public_key_pem": voter.public_key_pem}],
            "authorities": [{"authority_id": authority.authority_id, "public_key": str(authority.public_key)}],
        })
        self.assertEqual(int(exported["authorities"][0]["public_key"]), authority.public_key)
        exported["voters"][0]["public_key_pem"] = "alterada"
        self.assertEqual(self.registration.get_voter("eleitor_001"), voter)
        with self.assertRaises(FrozenInstanceError):
            voter.public_key_pem = "alterada"
        with self.assertRaises(FrozenInstanceError):
            authority.public_key = 1

    def test_different_elections_have_separate_registries(self):
        another = Registration("eleicao_2027", p=P, q=Q, state_provider=lambda: "CADASTRO")
        self.registration.register_voter("eleitor_001", self.pem)
        self.assertEqual(another.export_public_data()["voters"], [])
        another.register_voter("eleitor_001", self.pem)
        self.assertEqual(another.export_public_data()["election_id"], "eleicao_2027")

    def test_reject_inconsistent_or_small_group_parameters(self):
        for p, q in ((23, 11), (P, 2), (P, Q + 2), (P + 1, Q), (True, Q), (P, "q")):
            with self.subTest(p=p, q=q):
                with self.assertRaises(ValueError):
                    Registration("eleicao_2026", p=p, q=q, state_provider=lambda: "CADASTRO")


if __name__ == "__main__":
    unittest.main()
