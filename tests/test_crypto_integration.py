"""Integração da main com cadastro, assinaturas e quadro público.

Usa o grupo padrão de 2048 bits e cifras reais, sem importar a fixture P/Q.
As chaves privadas existem somente neste processo de teste, que simula os
participantes. Isso NÃO implementa isolamento real das autoridades.

O esquema assinado continua na versão 1: provas são conferidas separadamente
no teste, mas ainda não podem ser transportadas na cédula. A rejeição desse
campo é exercitada explicitamente para não confundir este teste com um fluxo
eleitoral completo. A branch de autoridades do Pedro não está integrada aqui.
"""

from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from src.bulletin_board.board import BulletinBoard
from src.bulletin_board.hash_chain import DuplicateVoteError, read_records, verify_board
from src.crypto.ballots import BallotFormatError, sign_ballot
from src.crypto.bit_proof import prove_bit, verify_bit_proof
from src.crypto.elgamal import Ciphertext, bounded_discrete_log, derive_public_key, encrypt_bit
from src.crypto.group import DEFAULT_PARAMETERS, random_scalar, validate_parameters
from src.crypto.homomorphic import aggregate_ciphertexts, decrypt_aggregate_with_partials
from src.crypto.keys import public_key_to_pem
from src.crypto.signatures import generate_signing_key
from src.server.registration import Registration


class CryptoIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.group = DEFAULT_PARAMETERS
        cls.signing_keys = [generate_signing_key(2048) for _ in range(3)]
        cls.authority_secrets = [random_scalar(cls.group.q) for _ in range(3)]
        cls.authority_keys = [derive_public_key(x, cls.group) for x in cls.authority_secrets]

    def setUp(self):
        self.registration = Registration(
            "integracao_2026", p=self.group.p, q=self.group.q,
            state_provider=lambda: "CADASTRO",
        )
        for index, key in enumerate(self.signing_keys, start=1):
            self.registration.register_voter(f"v{index}", public_key_to_pem(key.public_key()))
        for index, public_key in enumerate(self.authority_keys, start=1):
            self.registration.register_authority(f"a{index}", public_key)
        self.registration.freeze()

        # Montagem da chave pública apenas para o teste. Não somamos segredos.
        self.joint_key = 1
        for public_key in self.authority_keys:
            self.joint_key = self.joint_key * public_key % self.group.p
        self.assertNotEqual(self.joint_key, 1)
        public = self.registration.export_public_data()
        self.context = {
            "election_id": public["election_id"], "candidate_ids": ["A", "B"],
            "voter_public_keys": {v["voter_id"]: v["public_key_pem"] for v in public["voters"]},
        }

    def test_registration_accepts_main_group_and_authority_keys(self):
        validate_parameters(self.group)
        public = self.registration.export_public_data()
        self.assertTrue(public["frozen"])
        self.assertEqual(len(public["voters"]), 3)
        self.assertEqual(
            [int(a["public_key"]) for a in public["authorities"]], self.authority_keys
        )
        self.assertGreaterEqual(self.group.p.bit_length(), 2048)

    def test_real_ballots_roundtrip_board_and_aggregate_totals(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "bulletin_board.jsonl"
            board = BulletinBoard.create(path, **self.context)
            # Duas escolhas para A e uma para B. A regra de uma escolha ainda
            # não é provada pelo protocolo; aqui ela é uma entrada do cenário.
            envelopes = []
            for index, messages in enumerate(((1, 0), (0, 1), (1, 0)), start=1):
                ciphertexts = []
                for candidate_id, message in zip(self.context["candidate_ids"], messages):
                    ciphertext, randomness = encrypt_bit(message, self.joint_key, self.group)
                    # Contexto apenas deste teste; o formato público definitivo
                    # das provas e sua vinculação à cédula serão combinados.
                    proof_context = f"integracao_2026:v{index}:{candidate_id}".encode("ascii")
                    proof = prove_bit(
                        ciphertext, self.joint_key, randomness, message, self.group,
                        context=proof_context,
                    )
                    self.assertTrue(verify_bit_proof(
                        ciphertext, self.joint_key, proof, self.group, context=proof_context,
                    ))
                    # Adaptação explícita: objeto (a,b) -> campos JSON (c1,c2).
                    # Nenhum segredo ou aleatoriedade é colocado no quadro.
                    ciphertexts.append({
                        "candidate_id": candidate_id, "c1": str(ciphertext.a), "c2": str(ciphertext.b),
                    })
                envelope = sign_ballot({
                    "schema_version": 1, "election_id": "integracao_2026",
                    "voter_id": f"v{index}", "ciphertexts": ciphertexts,
                }, self.signing_keys[index - 1])
                board.append(envelope)
                envelopes.append(envelope)

            with self.assertRaises(DuplicateVoteError):
                board.append(envelopes[0])
            # Referência preservada no teste: não implementa testemunha externa.
            checkpoint = board.checkpoint
            with path.open("rb") as stream:
                self.assertEqual(verify_board(
                    read_records(stream), **self.context, expected_checkpoint=checkpoint,
                ), checkpoint)
            reopened = BulletinBoard(path, **self.context, expected_checkpoint=checkpoint)
            records = reopened.records()

            totals = []
            for position in range(2):
                column = [r["ballot"]["ciphertexts"][position] for r in records]
                aggregate = aggregate_ciphertexts(
                    [Ciphertext(a=int(c["c1"]), b=int(c["c2"])) for c in column], self.group,
                )
                # O teste simula cada autoridade contribuindo separadamente.
                # Somente cifras agregadas recebem parcelas de decifração.
                partials = [pow(aggregate.a, x, self.group.p) for x in self.authority_secrets]
                encoded_total = decrypt_aggregate_with_partials(aggregate, partials, self.group)
                totals.append(bounded_discrete_log(encoded_total, self.group, maximum=len(records)))
            self.assertEqual(totals, [2, 1])

    def test_current_schema_rejects_proofs_until_contract_is_extended(self):
        ciphertext, randomness = encrypt_bit(1, self.joint_key, self.group)
        proof = prove_bit(ciphertext, self.joint_key, randomness, 1, self.group)
        ballot = {
            "schema_version": 1, "election_id": "integracao_2026", "voter_id": "v1",
            "ciphertexts": [
                {"candidate_id": "A", "c1": str(ciphertext.a), "c2": str(ciphertext.b), "proof": asdict(proof)},
                {"candidate_id": "B", "c1": str(ciphertext.a), "c2": str(ciphertext.b)},
            ],
        }
        with self.assertRaises(BallotFormatError):
            sign_ballot(ballot, self.signing_keys[0])


if __name__ == "__main__":
    unittest.main()
