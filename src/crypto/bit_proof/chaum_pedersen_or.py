"""Prova OR de Chaum-Pedersen para validar uma cifra de bit.

O eleitor conhece r tal que a = g^r e prova que uma das afirmações é válida:

    b       = h^r        (mensagem 0)
    b / g   = h^r        (mensagem 1)

A prova não revela qual afirmação é a verdadeira.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from ..elgamal import Ciphertext
from ..group import DEFAULT_PARAMETERS, GroupParameters, inverse_mod, random_scalar


@dataclass(frozen=True)
class BitProof:
    """Compromissos, desafios e respostas das duas ramificações da prova."""

    commitment_g_0: int
    commitment_h_0: int
    challenge_0: int
    response_0: int
    commitment_g_1: int
    commitment_h_1: int
    challenge_1: int
    response_1: int


def _statement_value(
    ciphertext: Ciphertext,
    message: int,
    parameters: GroupParameters,
) -> int:
    """Retorna b/g^message, a segunda base da igualdade de logaritmos."""

    if message == 0:
        return ciphertext.b
    return (ciphertext.b * inverse_mod(parameters.g, parameters.p)) % parameters.p


def _encode_integer(value: int, size: int) -> bytes:
    return value.to_bytes(size, byteorder="big")


def _challenge(
    ciphertext: Ciphertext,
    public_key: int,
    commitments: tuple[int, int, int, int],
    context: bytes,
    parameters: GroupParameters,
) -> int:
    """Converte o transcript público em um desafio Fiat-Shamir."""

    size = (parameters.p.bit_length() + 7) // 8
    payload = b"URNA_ONLINE-BIT-PROOF-v1"
    payload += len(context).to_bytes(4, "big") + context
    for value in (public_key, ciphertext.a, ciphertext.b, *commitments):
        payload += _encode_integer(value, size)
    return int.from_bytes(hashlib.sha256(payload).digest(), "big") % parameters.q


def prove_bit(
    ciphertext: Ciphertext,
    public_key: int,
    randomness: int,
    message: int,
    parameters: GroupParameters = DEFAULT_PARAMETERS,
    *,
    context: bytes = b"",
) -> BitProof:
    """Cria uma prova de que ciphertext cifra 0 ou 1."""

    if message not in (0, 1):
        raise ValueError("a prova de bit aceita apenas a mensagem 0 ou 1")
    if not 1 <= randomness < parameters.q:
        raise ValueError("a aleatoriedade precisa estar em [1, q - 1]")

    fake_branch = 1 - message
    fake_challenge = secrets.randbelow(parameters.q)
    fake_response = secrets.randbelow(parameters.q)
    fake_statement = _statement_value(ciphertext, fake_branch, parameters)

    fake_commitment_g = (
        pow(parameters.g, fake_response, parameters.p)
        * inverse_mod(pow(ciphertext.a, fake_challenge, parameters.p), parameters.p)
    ) % parameters.p
    fake_commitment_h = (
        pow(public_key, fake_response, parameters.p)
        * inverse_mod(pow(fake_statement, fake_challenge, parameters.p), parameters.p)
    ) % parameters.p

    true_nonce = random_scalar(parameters.q)
    true_commitment_g = pow(parameters.g, true_nonce, parameters.p)
    true_commitment_h = pow(public_key, true_nonce, parameters.p)

    commitments_by_branch = [None, None]
    commitments_by_branch[fake_branch] = (fake_commitment_g, fake_commitment_h)
    commitments_by_branch[message] = (true_commitment_g, true_commitment_h)
    all_commitments = (
        commitments_by_branch[0][0],
        commitments_by_branch[0][1],
        commitments_by_branch[1][0],
        commitments_by_branch[1][1],
    )

    total_challenge = _challenge(
        ciphertext, public_key, all_commitments, context, parameters
    )
    true_challenge = (total_challenge - fake_challenge) % parameters.q
    true_response = (true_nonce + true_challenge * randomness) % parameters.q

    challenges = [None, None]
    responses = [None, None]
    challenges[fake_branch] = fake_challenge
    responses[fake_branch] = fake_response
    challenges[message] = true_challenge
    responses[message] = true_response

    return BitProof(
        commitment_g_0=all_commitments[0],
        commitment_h_0=all_commitments[1],
        challenge_0=challenges[0],
        response_0=responses[0],
        commitment_g_1=all_commitments[2],
        commitment_h_1=all_commitments[3],
        challenge_1=challenges[1],
        response_1=responses[1],
    )


def verify_bit_proof(
    ciphertext: Ciphertext,
    public_key: int,
    proof: BitProof,
    parameters: GroupParameters = DEFAULT_PARAMETERS,
    *,
    context: bytes = b"",
) -> bool:
    """Verifica a prova sem descobrir se a mensagem era 0 ou 1."""

    challenges = (proof.challenge_0, proof.challenge_1)
    responses = (proof.response_0, proof.response_1)
    commitments = (
        proof.commitment_g_0,
        proof.commitment_h_0,
        proof.commitment_g_1,
        proof.commitment_h_1,
    )

    if any(not 0 <= value < parameters.q for value in (*challenges, *responses)):
        return False
    if any(value == 0 or value >= parameters.p for value in commitments):
        return False

    expected = _challenge(ciphertext, public_key, commitments, context, parameters)
    if (proof.challenge_0 + proof.challenge_1) % parameters.q != expected:
        return False

    for message, challenge, response, commitment_g, commitment_h in (
        (0, proof.challenge_0, proof.response_0, proof.commitment_g_0, proof.commitment_h_0),
        (1, proof.challenge_1, proof.response_1, proof.commitment_g_1, proof.commitment_h_1),
    ):
        statement = _statement_value(ciphertext, message, parameters)
        left_g = pow(parameters.g, response, parameters.p)
        right_g = (commitment_g * pow(ciphertext.a, challenge, parameters.p)) % parameters.p
        left_h = pow(public_key, response, parameters.p)
        right_h = (commitment_h * pow(statement, challenge, parameters.p)) % parameters.p
        if left_g != right_g or left_h != right_h:
            return False

    return True


