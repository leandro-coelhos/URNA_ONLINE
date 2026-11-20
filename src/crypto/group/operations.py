"""Operações matemáticas e validações do grupo modular."""

from __future__ import annotations

import secrets

from .parameters import GroupParameters


def is_probable_prime(number: int, rounds: int = 32) -> bool:
    """Executa um teste probabilístico de Miller-Rabin.

    Ele é usado na configuração para conferir números fornecidos pelo grupo.
    Não é necessário repetir o teste a cada voto: p e q são parâmetros públicos
    fixos e já vêm de uma especificação padronizada.
    """

    if number in (2, 3):
        return True
    if number < 2 or number % 2 == 0:
        return False

    odd_part = number - 1
    powers_of_two = 0
    while odd_part % 2 == 0:
        powers_of_two += 1
        odd_part //= 2

    for _ in range(rounds):
        base = secrets.randbelow(number - 3) + 2
        value = pow(base, odd_part, number)
        if value in (1, number - 1):
            continue

        for _ in range(powers_of_two - 1):
            value = pow(value, 2, number)
            if value == number - 1:
                break
        else:
            return False

    return True


def validate_parameters(
    parameters: GroupParameters,
    *,
    check_primality: bool = False,
) -> None:
    """Valida as propriedades necessárias para o subgrupo usado pelo projeto.

    A checagem de primalidade é opcional porque pode ser custosa para números
    de 2048 bits. Ela deve ser executada durante a configuração ou em testes;
    as operações normais só precisam das verificações estruturais.
    """

    p, q, g = parameters.p, parameters.q, parameters.g

    if p.bit_length() < 2048:
        raise ValueError("p precisa possuir pelo menos 2048 bits")
    if p <= 3 or p % 2 == 0:
        raise ValueError("p precisa ser um inteiro ímpar maior que 3")
    if q <= 2 or q % 2 == 0:
        raise ValueError("q precisa ser um inteiro ímpar maior que 2")
    if (p - 1) % q != 0:
        raise ValueError("q precisa dividir p - 1")
    if not 1 < g < p:
        raise ValueError("g precisa estar entre 1 e p")
    if pow(g, q, p) != 1:
        raise ValueError("g não pertence ao subgrupo de ordem q")
    if g == 1:
        raise ValueError("g não pode ser igual a 1")

    if check_primality:
        if not is_probable_prime(p):
            raise ValueError("p não passou no teste de primalidade")
        if not is_probable_prime(q):
            raise ValueError("q não passou no teste de primalidade")


def inverse_mod(value: int, modulus: int) -> int:
    """Calcula o inverso multiplicativo de value módulo modulus."""

    value %= modulus
    if value == 0:
        raise ValueError("zero não possui inverso modular")
    try:
        return pow(value, -1, modulus)
    except ValueError as error:
        raise ValueError("o valor não possui inverso modular") from error


def random_scalar(order: int) -> int:
    """Gera um escalar uniforme no intervalo [1, order - 1]."""

    if order <= 2:
        raise ValueError("a ordem precisa ser maior que 2")
    return secrets.randbelow(order - 1) + 1


def is_group_element(value: int, parameters: GroupParameters) -> bool:
    """Verifica se value é um elemento não nulo do subgrupo escolhido."""

    return (
        1 <= value < parameters.p
        and pow(value, parameters.q, parameters.p) == 1
    )


