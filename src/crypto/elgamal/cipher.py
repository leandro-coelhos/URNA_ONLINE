"""Cifragem ElGamal exponencial para mensagens binárias."""

from __future__ import annotations

from dataclasses import dataclass

from ..group import (
    DEFAULT_PARAMETERS,
    GroupParameters,
    inverse_mod,
    is_group_element,
    random_scalar,
)


@dataclass(frozen=True)
class Ciphertext:
    """Um par (a, b) da cifra ElGamal."""

    a: int
    b: int


def derive_public_key(
    private_key: int,
    parameters: GroupParameters = DEFAULT_PARAMETERS,
) -> int:
    """Calcula h = g^x mod p a partir de uma chave privada x."""

    if not 1 <= private_key < parameters.q:
        raise ValueError("a chave privada precisa estar em [1, q - 1]")
    return pow(parameters.g, private_key, parameters.p)


def encrypt_bit(
    message: int,
    public_key: int,
    parameters: GroupParameters = DEFAULT_PARAMETERS,
    *,
    randomness: int | None = None,
) -> tuple[Ciphertext, int]:
    """Cifra uma mensagem 0/1 e retorna (cifra, r).

    O r é devolvido porque o eleitor precisa dele para produzir a prova de
    que a cifra representa um bit. Ele deve ser mantido secreto e nunca deve
    aparecer no recibo ou no quadro público.
    """

    if message not in (0, 1):
        raise ValueError("ElGamal exponencial deste módulo aceita apenas 0 ou 1")
    if not is_group_element(public_key, parameters):
        raise ValueError("a chave pública não pertence ao subgrupo esperado")

    r = randomness if randomness is not None else random_scalar(parameters.q)
    if not 1 <= r < parameters.q:
        raise ValueError("a aleatoriedade precisa estar em [1, q - 1]")

    a = pow(parameters.g, r, parameters.p)
    b = (pow(parameters.g, message, parameters.p) * pow(public_key, r, parameters.p)) % parameters.p
    return Ciphertext(a=a, b=b), r


def decrypt_to_group_element(
    ciphertext: Ciphertext,
    private_key: int,
    parameters: GroupParameters = DEFAULT_PARAMETERS,
) -> int:
    """Remove a parte de ElGamal e retorna g^m.

    Para a apuração, esta função deve receber a cifra agregada e a chave
    conjunta. Ela não recupera diretamente m; isso é feito por uma busca
    limitada em bounded_discrete_log.
    """

    if not 1 <= private_key < parameters.q:
        raise ValueError("a chave privada precisa estar em [1, q - 1]")
    if not is_group_element(ciphertext.a, parameters) or not is_group_element(ciphertext.b, parameters):
        raise ValueError("a cifra não pertence ao subgrupo esperado")

    shared = pow(ciphertext.a, private_key, parameters.p)
    return (ciphertext.b * inverse_mod(shared, parameters.p)) % parameters.p


def bounded_discrete_log(
    group_element: int,
    parameters: GroupParameters = DEFAULT_PARAMETERS,
    *,
    maximum: int,
) -> int:
    """Encontra m em g^m quando 0 <= m <= maximum.

    O total de votos é pequeno em relação ao tamanho do grupo, então não se
    tenta resolver um logaritmo discreto geral. A busca percorre apenas o
    intervalo possível para a eleição.
    """

    if maximum < 0:
        raise ValueError("maximum precisa ser não negativo")
    if not is_group_element(group_element, parameters):
        raise ValueError("o elemento não pertence ao subgrupo esperado")

    current = 1
    for value in range(maximum + 1):
        if current == group_element:
            return value
        current = (current * parameters.g) % parameters.p
    raise ValueError("não foi encontrado logaritmo no intervalo informado")


