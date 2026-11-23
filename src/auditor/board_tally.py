"""Cifras do quadro público e produto homomórfico: código comum.

Usado por dois consumidores que NÃO confiam no servidor:

- o auditor (``src.auditor.auditor``), que recalcula o agregado a partir do
  quadro e acumula os problemas num relatório;
- cada autoridade (``src.authorities.partial_decryption``), que recalcula o
  agregado antes de decifrar e recusa ao primeiro problema.

Por isso o módulo é puro: recebe registros já lidos, devolve inteiros ou
lança ``BoardTallyError`` com uma mensagem pronta. Não lê arquivos, não
guarda estado e não decide o que fazer com o erro.

Código compartilhado e independência do auditor
-----------------------------------------------
O auditor COMPARTILHA com a apuração este código: a leitura das cifras de
cada registro do quadro, a checagem de subgrupo/``c1`` repetido e o produto
homomórfico por candidato (``aggregate_columns`` é usado pelo auditor, por
``build_aggregate`` e pela conferência das autoridades). A independência do
auditor é de DADOS (lê só os arquivos públicos, nunca ``data/private/`` nem
o estado do servidor) e de SERVIDOR (não importa ``src.server``,
``src.election`` nem ``src.authorities``); NÃO é independência de
implementação. Um defeito aqui afetaria a apuração e o auditor do mesmo
modo, e o auditor não o detectaria. A verificação das provas de
Chaum-Pedersen das parcelas, essa sim, continua reimplementada no auditor.

O que este módulo NÃO FAZ
-------------------------
- Importa SOMENTE ``src.crypto`` (mesma regra do resto de ``src/auditor/``,
  conferida pelo teste AST do auditor). Quem importa daqui são as
  autoridades; este módulo não importa nada delas nem do servidor.
- Não verifica cadeia de hashes nem assinaturas: o auditor faz isso com
  ``src.bulletin_board.hash_chain``/``src.crypto.ballots`` e as autoridades
  com ``hash_chain.verify_board``.
- Não reimplementa primitivas: o produto é
  ``src.crypto.homomorphic.aggregate_ciphertexts``; a exponenciação modular é
  o ``pow`` nativo (padrão do projeto).
"""

from __future__ import annotations

from collections.abc import Iterable, MutableMapping, Sequence

from src.crypto.elgamal import Ciphertext
from src.crypto.group import GroupParameters
from src.crypto.homomorphic import aggregate_ciphertexts

__all__ = [
    "BoardTallyError",
    "aggregate_columns",
    "parse_decimal",
    "record_ciphertexts",
    "register_ciphertexts",
]

Pair = tuple[int, int]


class BoardTallyError(ValueError):
    """Registro do quadro com cifras inutilizáveis para o produto homomórfico."""


def parse_decimal(value: object, what: str) -> int:
    """``int`` estrito ou string decimal canônica (formato dos JSON públicos).

    Rejeita ``bool``, ``float``, sinais, espaços, ``_``, dígitos não ASCII e
    zeros à esquerda: um mesmo número tem uma única representação aceita.
    """
    if type(value) is int:
        return value
    if (
        isinstance(value, str)
        and value.isascii()
        and value.isdigit()
        and (value == "0" or not value.startswith("0"))
    ):
        return int(value)
    raise BoardTallyError(f"{what} deve ser inteiro (int ou string decimal)")


def record_ciphertexts(record: dict, candidates: Sequence[str], p: int) -> tuple[Pair, ...]:
    """Pares ``(c1, c2)`` da cédula de um registro, na ordem de ``candidates``.

    Confere a forma de cada cifra, o candidato de cada posição e o intervalo
    ``[2, p-1]``. O subgrupo e a repetição de ``c1`` ficam em
    ``register_ciphertexts``.
    """
    ballot = record.get("ballot") if type(record) is dict else None
    if type(ballot) is not dict:
        raise BoardTallyError("registro sem a cédula (campo ballot)")
    raw = ballot.get("ciphertexts")
    if type(raw) is not list or len(raw) != len(candidates):
        raise BoardTallyError(f"esperadas {len(candidates)} cifras, uma por candidato")
    pairs = []
    for position, (item, candidate_id) in enumerate(zip(raw, candidates)):
        if type(item) is not dict or set(item) != {"candidate_id", "c1", "c2"}:
            raise BoardTallyError(f"cifra {position} deve ter exatamente candidate_id, c1 e c2")
        if item["candidate_id"] != candidate_id:
            raise BoardTallyError(
                f"cifra {position} é de {item['candidate_id']!r}, esperado {candidate_id!r}"
            )
        c1 = parse_decimal(item["c1"], f"c1 da cifra {position}")
        c2 = parse_decimal(item["c2"], f"c2 da cifra {position}")
        if not (2 <= c1 <= p - 1 and 2 <= c2 <= p - 1):
            raise BoardTallyError(f"cifra {position} fora de [2, p-1]")
        pairs.append((c1, c2))
    return tuple(pairs)


def register_ciphertexts(
    pairs: Sequence[Pair], position: int, seen_c1: MutableMapping[int, int], *, p: int, q: int
) -> None:
    """Exige cifras no subgrupo de ordem ``q`` e ``c1`` inédito no quadro.

    ``seen_c1`` mapeia cada ``c1`` já visto à entrada em que apareceu e só é
    atualizado se a cédula inteira passar. Um ``c1`` repetido indica cifra
    copiada de outro eleitor: no produto, o voto copiado contaria duas vezes.
    """
    for index, (c1, c2) in enumerate(pairs):
        if pow(c1, q, p) != 1 or pow(c2, q, p) != 1:
            raise BoardTallyError(f"cifra {index} fora do subgrupo de ordem q")
        if c1 in seen_c1:
            raise BoardTallyError(
                f"c1 da cifra {index} repete o da entrada {seen_c1[c1]} (cifra copiada)"
            )
    for c1, _ in pairs:
        seen_c1[c1] = position


def aggregate_columns(
    ballots: Iterable[Sequence[Pair]], n_candidates: int, *, p: int, q: int, g: int
) -> tuple[Pair, ...]:
    """``(Π c1, Π c2)`` de cada posição de candidato, com ``aggregate_ciphertexts``.

    Cada cédula precisa ter exatamente ``n_candidates`` pares (o chamador já
    validou a forma). Exige ao menos uma cédula.
    """
    columns: list[list[Ciphertext]] = [[] for _ in range(n_candidates)]
    for pairs in ballots:
        if len(pairs) != n_candidates:
            raise BoardTallyError(f"esperadas {n_candidates} cifras, uma por candidato")
        for column, (c1, c2) in zip(columns, pairs):
            column.append(Ciphertext(a=c1, b=c2))
    if not columns or not columns[0]:
        raise BoardTallyError("não há cédulas para agregar")
    parameters = GroupParameters(p=p, q=q, g=g)
    products = (aggregate_ciphertexts(column, parameters) for column in columns)
    return tuple((product.a, product.b) for product in products)
