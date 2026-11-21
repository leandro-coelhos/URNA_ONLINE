"""Agregação de cifras sem decifrar votos individuais."""

from __future__ import annotations

from collections.abc import Iterable

from ..elgamal import Ciphertext
from ..group import DEFAULT_PARAMETERS, GroupParameters, inverse_mod


def aggregate_ciphertexts(
    ciphertexts: Iterable[Ciphertext],
    parameters: GroupParameters = DEFAULT_PARAMETERS,
) -> Ciphertext:
    """Multiplica cifras ElGamal de uma mesma opção de candidato."""

    result_a = 1
    result_b = 1
    count = 0
    for ciphertext in ciphertexts:
        result_a = (result_a * ciphertext.a) % parameters.p
        result_b = (result_b * ciphertext.b) % parameters.p
        count += 1

    if count == 0:
        raise ValueError("não é possível agregar uma lista vazia")
    return Ciphertext(a=result_a, b=result_b)


def combine_partial_decryptions(
    partials: Iterable[int],
    parameters: GroupParameters = DEFAULT_PARAMETERS,
) -> int:
    """Combina as parcelas a^x_i enviadas pelas autoridades."""

    combined = 1
    count = 0
    for partial in partials:
        if not 1 <= partial < parameters.p:
            raise ValueError("parcela de autoridade fora do intervalo")
        combined = (combined * partial) % parameters.p
        count += 1

    if count == 0:
        raise ValueError("a apuração exige pelo menos uma autoridade")
    return combined


def decrypt_aggregate_with_partials(
    aggregate: Ciphertext,
    partials: Iterable[int],
    parameters: GroupParameters = DEFAULT_PARAMETERS,
) -> int:
    """Remove a chave conjunta da cifra agregada e retorna g^total."""

    shared_factor = combine_partial_decryptions(partials, parameters)
    return (aggregate.b * inverse_mod(shared_factor, parameters.p)) % parameters.p


