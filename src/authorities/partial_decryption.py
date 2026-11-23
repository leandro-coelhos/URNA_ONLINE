"""Decifração conjunta do resultado: parcelas das autoridades (Issue #11).

Contexto matemático
-------------------
Para cada candidato, a apuração produz a cifra agregada::

    (C1, C2) = (g^R, g^T · h^R mod p),   h = Π h_i = g^(Σ x_i)

em que ``T`` é o total de votos. Cada autoridade ``i`` calcula, no próprio
processo, ``d_i = C1^(x_i) mod p``. Como ``Π d_i = C1^(Σ x_i) = h^R``, o
servidor obtém ``g^T = C2 · (Π d_i)^(-1) mod p`` sem que ``Σ x_i`` exista em
lugar algum. Faltando uma parcela, falta um fator: o resultado não sai.

Cada ``d_i`` acompanha uma prova não interativa de Chaum-Pedersen
(Fiat-Shamir com SHA-256) de que ``log_g(h_i) = log_C1(d_i)``: a autoridade
prova que usou a MESMA chave cadastrada, sem revelá-la. Sem a prova, uma
autoridade poderia enviar um ``d_i`` qualquer e falsificar o resultado.

O que este módulo FAZ
---------------------
- Lado da autoridade: ``compute_authority_partials`` calcula ``d_i`` e a
  prova de cada candidato, no processo local, a partir de ``Authority``.
- ANTES de decifrar, a autoridade confere o agregado recebido do servidor
  contra o quadro público que ela mesma lê (``board_path``): verifica a
  cadeia de hashes, as assinaturas, a elegibilidade e a unicidade com
  ``src.bulletin_board.hash_chain.verify_board``, recalcula o produto
  homomórfico de cada candidato e o nº de cédulas e recusa com
  ``AggregateVerificationError`` qualquer diferença. Sem isso, um servidor
  malicioso poderia enviar a cifra de UMA cédula como se fosse o agregado e
  descobrir o voto daquele eleitor (ver ``_verify_aggregate_against_board``).
- Lado do servidor: ``PartialDecryptionCollector`` (e o atalho
  ``verify_authority_partials``) aceita somente submissões de autoridades
  cadastradas, sem duplicidade, cobrindo exatamente os candidatos da cifra
  agregada e com provas válidas contra o ``h_i`` de ``election.json``.
- ``combine_and_decrypt_result`` exige TODAS as autoridades cadastradas,
  combina as parcelas, recupera os totais e publica ``result.json``.
- Limita cada total a ``[0, nº de cédulas]``, o mesmo critério do auditor.
  O nº de cédulas é o ``ballot_count`` de ``aggregate_ciphertexts.json``
  (cédulas aceitas que entraram no produto), não o nº de eleitores
  cadastrados: com abstenção, eleitores > cédulas.
- Exige que a soma dos totais seja IGUAL ao nº de cédulas (ver
  ``_check_totals_sum``); se não for, nada é publicado.
- Persiste ``authority_partials.json`` e ``result.json`` de forma atômica
  (``mkstemp`` + ``os.replace``), com inteiros grandes como strings decimais.

O que este módulo NÃO FAZ
-------------------------
- Não reimplementa primitivas: exponenciação modular (``pow`` nativo do
  Python, padrão do projeto), inverso modular
  (``src.crypto.group.inverse_mod``) e logaritmo discreto limitado
  (``src.crypto.elgamal.bounded_discrete_log``) vêm de ``src.crypto`` ou são
  injetados. O módulo só confere os valores devolvidos (``D · D^(-1) ≡ 1`` e
  ``g^tally ≡ M``).
- ``build_aggregate``/``publish_aggregate`` montam ``aggregate_ciphertexts.json``
  com ``src.crypto.homomorphic.aggregate_ciphertexts`` (produto das cifras de
  cada candidato), já que ``src/server/tally.py`` não existe.
  A prova de Chaum-Pedersen usa apenas ``pow``, SHA-256 e aritmética
  módulo ``q``.
- ``build_aggregate``/``publish_aggregate`` não leem o quadro público nem
  mudam a etapa da eleição: quem chama fornece as cifras das cédulas aceitas
  (``Election.accepted_ballots``). Quem lê o quadro é a autoridade, em
  ``compute_authority_partials``.
- Não garante que o quadro lido pela autoridade seja o mesmo que todos veem:
  a autoridade confia nos arquivos que lê (quadro e ``election.json``). Sem
  um ``expected_checkpoint`` de fonte independente, um servidor que controle
  esses arquivos pode apresentar um quadro alternativo (por exemplo, só com
  a cédula de um eleitor, com a cadeia recalculada) e ele será aceito. É a
  mesma limitação da remoção da última cédula (cenário 4c da T14).
- Nunca grava, devolve ou inclui em exceções ``x_i`` ou o valor efêmero
  ``w``. As estruturas de submissão carregam apenas dados públicos.
- Não garante que cada voto cifrado seja 0 ou 1 (não há prova 0/1 no
  formato da cédula). A verificação da soma é uma mitigação PARCIAL e
  AGREGADA: detecta que alguma cédula não cifra exatamente um voto (ex.:
  ``m = 2`` ou 1 para os dois candidatos), mas não identifica qual eleitor
  foi, e combinações que preservam a soma de cada cédula (ex.: ``m = -1``
  para um candidato e ``m = 2`` para o outro) continuam indetectáveis.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Union

# Só o módulo comum de recálculo; a autoridade nunca usa a classe Auditor.
from src.auditor.board_tally import (
    BoardTallyError,
    aggregate_columns,
    record_ciphertexts,
    register_ciphertexts,
)
from src.authorities.authority import (
    MIN_AUTHORITIES,
    Authority,
    GroupParams,
    _atomic_write_json,  # escrita atômica do próprio pacote (mkstemp + os.replace)
    validate_authority_id,
)
from src.bulletin_board.hash_chain import make_checkpoint, read_records, verify_board
from src.crypto.elgamal import bounded_discrete_log
from src.crypto.group import GroupParameters, inverse_mod
from src.election.states import ElectionState

# Inverso modular real de src.crypto.group: mesma assinatura do contrato.
_default_mod_inv = inverse_mod

__all__ = [
    "DEFAULT_AGGREGATE_PATH",
    "DEFAULT_ELECTION_PATH",
    "DEFAULT_PARTIALS_PATH",
    "DEFAULT_RESULT_PATH",
    "PROOF_DOMAIN",
    "build_aggregate",
    "publish_aggregate",
    "crypto_discrete_log",
    "AggregateVerificationError",
    "AuthorityPartialSubmission",
    "CandidatePartialShare",
    "DecryptionError",
    "DuplicateShareError",
    "InconsistentTotalsError",
    "InvalidShareError",
    "MissingAuthorityShareError",
    "PartialDecryptionCollector",
    "PartialDecryptionError",
    "TallyStateError",
    "UnregisteredAuthorityError",
    "combine_and_decrypt_result",
    "compute_authority_partials",
    "load_public_json",
    "verify_authority_partials",
]

DEFAULT_ELECTION_PATH = Path("data/public/election.json")
DEFAULT_AGGREGATE_PATH = Path("data/public/aggregate_ciphertexts.json")
DEFAULT_PARTIALS_PATH = Path("data/public/authority_partials.json")
DEFAULT_RESULT_PATH = Path("data/public/result.json")

# Separador de domínio do desafio Fiat-Shamir: uma prova feita para outro
# protocolo (ou outra versão deste) não serve aqui.
PROOF_DOMAIN = "URNA_ONLINE/chaum-pedersen/v1"
PARTIALS_SCHEMA_VERSION = 1
AGGREGATE_SCHEMA_VERSION = 1
RESULT_SCHEMA_VERSION = 1
MAX_CANDIDATE_ID = 128

# Contratos das funções delegadas ao módulo de crypto:
#   mod_inv(value, mod) -> int                       (value · resultado ≡ 1 mod p)
#   discrete_log(target, base, mod, max_exp) -> int | None
#                                                    (menor t em [0, max_exp] com base^t ≡ target)
# Se a interface real for outra, injete um adaptador.
ModInv = Callable[[int, int], int]
DiscreteLog = Callable[[int, int, int, int], Union[int, None]]
StateSource = Union[ElectionState, str, Callable[[], str], None]


# ------------------------------------------------------------------------ erros
class PartialDecryptionError(ValueError):
    """Base dos erros da decifração conjunta. Mensagens nunca contêm segredos."""


class TallyStateError(PartialDecryptionError):
    """Cadastro não congelado ou eleição fora de ``APURACAO``."""


class UnregisteredAuthorityError(PartialDecryptionError):
    """A autoridade não consta em ``election.json["authorities"]``."""


class DuplicateShareError(PartialDecryptionError):
    """A autoridade já enviou sua submissão; a primeira é preservada."""


class InvalidShareError(PartialDecryptionError):
    """Submissão malformada, incompleta ou com prova de Chaum-Pedersen inválida."""


class MissingAuthorityShareError(PartialDecryptionError):
    """Nem todas as autoridades cadastradas enviaram parcela válida."""


class DecryptionError(PartialDecryptionError):
    """O total não pôde ser recuperado dentro de ``[0, max_votes]``."""


class AggregateVerificationError(PartialDecryptionError):
    """A autoridade recusa decifrar: o agregado não confere com o quadro público.

    Lançada por ``compute_authority_partials`` ANTES de qualquer uso de
    ``x_i`` quando o quadro lido pela autoridade é inválido (cadeia,
    assinatura, elegibilidade, unicidade, cifras) ou quando as cifras de
    algum candidato, o conjunto de candidatos ou o ``ballot_count`` diferem
    do recalculado a partir dele. Nenhuma parcela é produzida.
    """


class InconsistentTotalsError(DecryptionError):
    """A soma dos totais difere do número de cédulas: o resultado não é publicado.

    Detecção AGREGADA (sem prova 0/1): indica que ao menos uma cédula não
    cifra exatamente um voto, mas não qual. Não pega cédulas que preservam a
    soma (ex.: ``m = -1`` e ``m = 2`` na mesma cédula).
    """


# ------------------------------------------------------- estruturas públicas
@dataclass(frozen=True)
class CandidatePartialShare:
    """Parcela pública de UMA autoridade para UM candidato.

    ``d`` é ``d_i = C1^(x_i) mod p``; ``(a1, a2, s)`` é a prova de
    Chaum-Pedersen. Nenhum campo depende de forma recuperável de ``x_i`` ou ``w``
    (``s = w + c·x_i mod q`` é seguro porque ``w`` é aleatório e descartado).
    """

    candidate_id: str
    d: int
    a1: int
    a2: int
    s: int

    def __post_init__(self) -> None:
        _validate_candidate_id(self.candidate_id, InvalidShareError)
        for name in ("d", "a1", "a2", "s"):
            # type(...) is int: bool é subclasse de int e não é um valor válido.
            if type(getattr(self, name)) is not int:
                raise InvalidShareError(f"{name} da parcela de {self.candidate_id!r} deve ser int")

    def to_dict(self) -> dict:
        return {"d": str(self.d), "a1": str(self.a1), "a2": str(self.a2), "s": str(self.s)}


@dataclass(frozen=True)
class AuthorityPartialSubmission:
    """O que uma autoridade envia ao servidor: id e uma parcela por candidato.

    Imutável e só com dados públicos. As parcelas são ordenadas por
    ``candidate_id`` para que a serialização seja determinística.
    """

    authority_id: str
    shares: tuple[CandidatePartialShare, ...]

    def __post_init__(self) -> None:
        try:
            validate_authority_id(self.authority_id)
        except ValueError:
            raise InvalidShareError("authority_id inválido") from None
        if type(self.shares) not in (tuple, list) or not self.shares:
            raise InvalidShareError("shares deve ser uma lista não vazia")
        if not all(type(share) is CandidatePartialShare for share in self.shares):
            raise InvalidShareError("cada item de shares deve ser CandidatePartialShare")
        ids = [share.candidate_id for share in self.shares]
        if len(set(ids)) != len(ids):
            raise InvalidShareError("candidato repetido na submissão")
        object.__setattr__(
            self, "shares", tuple(sorted(self.shares, key=lambda share: share.candidate_id))
        )

    @property
    def candidate_ids(self) -> frozenset[str]:
        return frozenset(share.candidate_id for share in self.shares)

    def share_for(self, candidate_id: str) -> CandidatePartialShare:
        for share in self.shares:
            if share.candidate_id == candidate_id:
                return share
        raise InvalidShareError(f"sem parcela para o candidato {candidate_id!r}")

    def to_dict(self) -> dict:
        return {
            "authority_id": self.authority_id,
            "shares": {share.candidate_id: share.to_dict() for share in self.shares},
        }

    @classmethod
    def from_dict(cls, data: object) -> "AuthorityPartialSubmission":
        """Reconstrói a submissão de JSON, com tipos estritos e campos exatos."""
        if type(data) is not dict or set(data) != {"authority_id", "shares"}:
            raise InvalidShareError("submissão deve ter exatamente authority_id e shares")
        raw_shares = data["shares"]
        if type(raw_shares) is not dict or not raw_shares:
            raise InvalidShareError("shares deve ser um objeto não vazio")
        shares = []
        for candidate_id, raw in raw_shares.items():
            if type(raw) is not dict or set(raw) != {"d", "a1", "a2", "s"}:
                raise InvalidShareError(f"parcela de {candidate_id!r} deve ter exatamente d, a1, a2 e s")
            values = {
                name: _parse_int(raw[name], f"{name} de {candidate_id!r}", InvalidShareError)
                for name in ("d", "a1", "a2", "s")
            }
            shares.append(CandidatePartialShare(candidate_id, **values))
        return cls(data["authority_id"], tuple(shares))


# -------------------------------------------------------------------- helpers
def _canonical_json(obj: Any) -> bytes:
    """Mesmos dados, mesmos bytes: base do desafio Fiat-Shamir."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _parse_int(value: object, what: str, error: type[PartialDecryptionError]) -> int:
    """Aceita ``int`` estrito ou string decimal canônica (formato dos JSON públicos).

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
    raise error(f"{what} deve ser inteiro (int ou string decimal)")


def _validate_candidate_id(candidate_id: object, error: type[PartialDecryptionError]) -> None:
    # Mesma regra dos nomes de candidato em src.election.election.
    if (
        not isinstance(candidate_id, str)
        or not 1 <= len(candidate_id) <= MAX_CANDIDATE_ID
        or candidate_id != candidate_id.strip()
        or not candidate_id.isprintable()
    ):
        raise error(f"candidate_id inválido: {candidate_id!r}")


def _resolve(injected: Callable | None, default: Callable | None, name: str) -> Callable:
    function = injected if injected is not None else default
    if function is None:
        raise RuntimeError(f"{name} indisponível nesta branch; injete {name}=...")
    if not callable(function):
        raise TypeError(f"{name} deve ser uma função")
    return function


def _check_state(source: StateSource) -> None:
    """Se a etapa for informada (valor ou função), ela precisa ser ``APURACAO``."""
    if source is None:
        return
    value = source() if callable(source) else source
    try:
        state = ElectionState(value)
    except ValueError:
        raise TallyStateError(f"etapa desconhecida: {value!r}") from None
    if state is not ElectionState.APURACAO:
        raise TallyStateError(f"decifração só é permitida em APURACAO; etapa atual: {state.value}")


def load_public_json(path: Path | str) -> dict:
    """Lê um arquivo público (``election.json``, ``aggregate_ciphertexts.json``…)."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise PartialDecryptionError(f"{path} ilegível: {exc}") from exc
    if type(data) is not dict:
        raise PartialDecryptionError(f"{path} não contém um objeto JSON")
    return data


# ------------------------------------------------------- dados públicos lidos
@dataclass(frozen=True)
class _ElectionContext:
    election_id: str
    p: int
    q: int
    g: int
    authorities: MappingProxyType  # authority_id -> h_i, na ordem do cadastro
    voter_count: int | None
    candidates: tuple[str, ...] | None


def _parse_election(data: object) -> _ElectionContext:
    """Valida ``election.json``. Só chaves públicas são lidas."""
    if type(data) is not dict:
        raise PartialDecryptionError("election.json deve conter um objeto JSON")
    election_id = data.get("election_id")
    try:
        validate_authority_id(election_id)  # mesma regra de identificador
    except ValueError:
        raise PartialDecryptionError("election_id inválido em election.json") from None
    # Sem congelamento, o conjunto de autoridades (e portanto h) pode mudar.
    if data.get("frozen") is not True:
        raise TallyStateError("o cadastro precisa estar congelado")

    group = data.get("group")
    if type(group) is not dict:
        raise PartialDecryptionError("election.json sem os parâmetros do grupo")
    p = _parse_int(group.get("p"), "group.p", PartialDecryptionError)
    q = _parse_int(group.get("q"), "group.q", PartialDecryptionError)
    g = _parse_int(group.get("g"), "group.g", PartialDecryptionError)
    if (
        p.bit_length() < 2048
        or q.bit_length() < 224
        or not 2 < q < p
        or (p - 1) % q != 0
        or not 1 < g < p - 1
        or pow(g, q, p) != 1
    ):
        raise PartialDecryptionError("parâmetros de grupo incoerentes em election.json")

    raw = data.get("authorities")
    if not isinstance(raw, list) or len(raw) < MIN_AUTHORITIES:
        raise PartialDecryptionError(f"election.json deve ter pelo menos {MIN_AUTHORITIES} autoridades")
    authorities: dict[str, int] = {}
    for entry in raw:
        if type(entry) is not dict:
            raise PartialDecryptionError("registro de autoridade malformado")
        authority_id = entry.get("authority_id")
        try:
            validate_authority_id(authority_id)
        except ValueError:
            raise PartialDecryptionError("authority_id inválido em election.json") from None
        if authority_id in authorities:
            raise PartialDecryptionError(f"autoridade {authority_id!r} repetida em election.json")
        h_i = _parse_int(entry.get("public_key"), f"public_key de {authority_id!r}", PartialDecryptionError)
        # h_i fora do subgrupo tornaria a prova de Chaum-Pedersen inconsistente.
        if not 1 < h_i < p - 1 or pow(h_i, q, p) != 1:
            raise PartialDecryptionError(f"public_key de {authority_id!r} fora do subgrupo de ordem q")
        authorities[authority_id] = h_i

    # Defesa contra election.json adulterado: h publicado = Π h_i.
    if data.get("joint_public_key") is not None:
        joint = _parse_int(data["joint_public_key"], "joint_public_key", PartialDecryptionError)
        product = 1
        for h_i in authorities.values():
            product = product * h_i % p
        if joint != product:
            raise PartialDecryptionError("joint_public_key não corresponde ao produto das chaves")

    voters = data.get("voters")
    candidates = data.get("candidates")
    if candidates is not None:
        if not isinstance(candidates, list):
            raise PartialDecryptionError("candidates deve ser uma lista")
        for name in candidates:
            _validate_candidate_id(name, PartialDecryptionError)
        candidates = tuple(candidates)
    return _ElectionContext(
        election_id=election_id,
        p=p,
        q=q,
        g=g,
        authorities=MappingProxyType(authorities),
        voter_count=len(voters) if isinstance(voters, list) else None,
        candidates=candidates,
    )


def _parse_aggregate(data: object, ctx: _ElectionContext) -> MappingProxyType:
    """Valida ``aggregate_ciphertexts.json``: ``candidate_id -> (C1, C2)``."""
    if type(data) is not dict:
        raise PartialDecryptionError("aggregate_ciphertexts.json deve conter um objeto JSON")
    if data.get("election_id") != ctx.election_id:
        raise PartialDecryptionError("as cifras agregadas pertencem a outra eleição")
    raw = data.get("ciphertexts")
    if type(raw) is not dict or not raw:
        raise PartialDecryptionError("ciphertexts deve ser um objeto não vazio")
    if ctx.candidates is not None and set(raw) != set(ctx.candidates):
        raise AggregateVerificationError(
            "candidatos das cifras agregadas diferem dos da eleição: "
            f"faltando {sorted(set(ctx.candidates) - set(raw))}, "
            f"sobrando {sorted(set(raw) - set(ctx.candidates))}"
        )

    p, q = ctx.p, ctx.q
    parsed: dict[str, tuple[int, int]] = {}
    for candidate_id, entry in raw.items():
        _validate_candidate_id(candidate_id, PartialDecryptionError)
        if type(entry) is not dict or set(entry) != {"c1", "c2"}:
            raise PartialDecryptionError(f"cifra de {candidate_id!r} deve ter exatamente c1 e c2")
        pair = []
        for name in ("c1", "c2"):
            value = _parse_int(entry[name], f"{name} de {candidate_id!r}", PartialDecryptionError)
            # C1 = 1 tornaria d_i = 1 e a prova trivial; fora do subgrupo, d_i
            # poderia vazar informação sobre x_i.
            if not 2 <= value <= p - 1 or pow(value, q, p) != 1:
                raise PartialDecryptionError(
                    f"{name} de {candidate_id!r} fora de [2, p-1] ou do subgrupo de ordem q"
                )
            pair.append(value)
        parsed[candidate_id] = (pair[0], pair[1])
    return MappingProxyType(parsed)


def _aggregate_ballot_count(data: dict, ctx: _ElectionContext) -> int:
    """Nº de cédulas do agregado (``ballot_count``): o limite de cada total.

    É o mesmo critério do auditor, que usa o nº de registros do quadro
    público. Não pode passar do nº de eleitores cadastrados (cada um vota no
    máximo uma vez); menos cédulas que eleitores é abstenção.
    """
    if "ballot_count" not in data:
        raise PartialDecryptionError(
            "aggregate_ciphertexts.json sem ballot_count: o limite dos totais é o número de cédulas"
        )
    count = _parse_int(data["ballot_count"], "ballot_count", PartialDecryptionError)
    if count < 1:
        raise PartialDecryptionError("ballot_count deve ser >= 1")
    if ctx.voter_count is not None and count > ctx.voter_count:
        raise PartialDecryptionError(
            f"ballot_count ({count}) maior que o número de eleitores cadastrados ({ctx.voter_count})"
        )
    return count


def _check_totals_sum(totals: dict[str, int], ballot_count: int) -> None:
    """Exige ``Σ totais == nº de cédulas`` (mitigação parcial da falta da prova 0/1).

    Por que igualdade, e não ``<=``: o sistema não tem voto em branco. O
    enunciado define a cédula como uma cifra de 1 para o candidato escolhido
    e de 0 para os demais; os clientes honestos (``VoterClient.build_ballot``
    em ``demo.py`` e ``_choice_vector`` em ``tests/support``) sempre cifram
    exatamente um 1, e a lista de candidatos não tem opção "branco". Quem se
    abstém não envia cédula, então não entra em ``ballot_count``. Logo, cada
    cédula honesta soma 1 e o total é exatamente o nº de cédulas.

    Detecção AGREGADA: aponta que alguma cédula não soma 1 (``m = 2``, 1 para
    os dois candidatos, tudo 0…), mas não qual nem de que eleitor. Cédulas
    que somam 1 com valores fora de {0, 1} (ex.: ``m = -1`` e ``m = 2``)
    passam; só a prova 0/1 por cifra as detectaria.
    """
    total = sum(totals.values())
    if total != ballot_count:
        raise InconsistentTotalsError(
            f"soma dos totais ({total}) difere do número de cédulas ({ballot_count}): "
            "ao menos uma cédula não cifra exatamente um voto (detecção agregada, "
            "não identifica o eleitor); resultado não publicado"
        )


# ---------------------------------------------- adaptadores e agregação
def crypto_discrete_log(q: int) -> DiscreteLog:
    """Adapta ``src.crypto.elgamal.bounded_discrete_log`` ao contrato ``discrete_log``.

    ``bounded_discrete_log`` recebe os parâmetros do grupo (com ``q``, para
    conferir o pertencimento ao subgrupo) e usa ``g`` como base; aqui a base
    informada vira o ``g`` desses parâmetros. Valor fora de ``[0, max_exp]``
    devolve ``None``, como no contrato.
    """
    def discrete_log(target: int, base: int, modulus: int, max_exp: int) -> int | None:
        parameters = GroupParameters(p=modulus, q=q, g=base)
        try:
            return bounded_discrete_log(target, parameters, maximum=max_exp)
        except ValueError:
            return None

    return discrete_log


def build_aggregate(
    election_id: str,
    candidate_ids: Iterable[str],
    ballots: Iterable[Iterable[tuple[int, int]]],
    group: GroupParams,
) -> dict:
    """Produto homomórfico ``(Π c1, Π c2)`` por candidato, no formato de
    ``aggregate_ciphertexts.json``.

    ``ballots`` traz, para cada cédula aceita, um par ``(c1, c2)`` por
    candidato na ordem de ``candidate_ids`` (por exemplo,
    ``[b.ciphertexts for b in election.accepted_ballots]``). A multiplicação é
    a de ``src.crypto.homomorphic.aggregate_ciphertexts``. Exige ao menos uma
    cédula. Não decifra nada.
    """
    candidates = tuple(candidate_ids)
    if not candidates or len(set(candidates)) != len(candidates):
        raise PartialDecryptionError("informe candidatos distintos")
    for candidate_id in candidates:
        _validate_candidate_id(candidate_id, PartialDecryptionError)
    rows = []
    for position, pairs in enumerate(ballots):
        pairs = tuple(tuple(pair) for pair in pairs)
        if len(pairs) != len(candidates):
            raise PartialDecryptionError(
                f"cédula {position}: esperadas {len(candidates)} cifras, recebidas {len(pairs)}"
            )
        rows.append(pairs)
    if not rows:
        raise PartialDecryptionError("não há cédulas para agregar")
    # Mesmo produto que o auditor e a conferência da autoridade usam.
    products = aggregate_columns(rows, len(candidates), p=group.p, q=group.q, g=group.g)
    aggregate = {
        candidate_id: {"c1": str(c1), "c2": str(c2)}
        for candidate_id, (c1, c2) in zip(candidates, products)
    }
    return {
        "schema_version": AGGREGATE_SCHEMA_VERSION,
        "election_id": election_id,
        "ballot_count": len(rows),
        "ciphertexts": aggregate,
    }


def publish_aggregate(
    election_id: str,
    candidate_ids: Iterable[str],
    ballots: Iterable[Iterable[tuple[int, int]]],
    group: GroupParams,
    *,
    election_state: StateSource = None,
    aggregate_path: Path | str = DEFAULT_AGGREGATE_PATH,
) -> dict:
    """``build_aggregate`` + gravação atômica de ``aggregate_ciphertexts.json``.

    Se ``election_state`` for informado, exige ``APURACAO`` (a votação já foi
    encerrada): agregar antes disso publicaria um resultado parcial.
    """
    _check_state(election_state)
    aggregate = build_aggregate(election_id, candidate_ids, ballots, group)
    _atomic_write_json(Path(aggregate_path), aggregate)
    return aggregate


# ------------------------------------------- conferência do agregado (autoridade)
def _board_voter_keys(election_data: dict) -> dict[str, str]:
    """``voter_id -> chave pública`` do cadastro em ``election.json``.

    Aceita ``public_key`` ou ``public_key_pem`` (nome de
    ``Registration.export_public_data()``), como o auditor.
    """
    voters = election_data.get("voters")
    if not isinstance(voters, list) or not voters:
        raise AggregateVerificationError(
            "election.json sem o cadastro de eleitores: o quadro público não pode ser conferido"
        )
    keys: dict[str, str] = {}
    for entry in voters:
        voter_id = entry.get("voter_id") if type(entry) is dict else None
        key = entry.get("public_key", entry.get("public_key_pem")) if type(entry) is dict else None
        if not isinstance(voter_id, str) or not isinstance(key, str):
            raise AggregateVerificationError("registro de eleitor malformado em election.json")
        if voter_id in keys:
            raise AggregateVerificationError(f"eleitor {voter_id!r} repetido em election.json")
        keys[voter_id] = key
    return keys


def _board_invalid(exc: BaseException) -> AggregateVerificationError:
    return AggregateVerificationError(
        f"agregado recusado: quadro público inválido ({type(exc).__name__}: {exc})"
    )


def _verify_aggregate_against_board(
    ctx: _ElectionContext,
    election_data: dict,
    aggregate_data: dict,
    aggregate: MappingProxyType,
    board_path: Path | str,
    expected_checkpoint: dict | None,
) -> int:
    """Recalcula o agregado a partir do quadro público e exige igualdade exata.

    Por que a autoridade confere, em vez de confiar no servidor: ``d_i =
    C1^(x_i)`` remove a parte de ``h^R`` de QUALQUER cifra. Se o servidor
    enviasse a cifra de uma única cédula como "agregado", as parcelas de
    todas as autoridades a decifrariam e o voto daquele eleitor vazaria,
    possivelmente sem nada disso ser publicado.

    Passos (somente API pública de ``src.bulletin_board`` e ``src.crypto``):

    1. Lê o quadro com ``hash_chain.read_records`` (leitor estrito, sem
       ``fcntl``) e o verifica com ``hash_chain.verify_board``: índices, elos,
       hashes, formato, assinatura de cada cédula com a chave CADASTRADA do
       eleitor, elegibilidade e unicidade. As assinaturas são indispensáveis:
       ``hash_record`` e ``genesis_hash`` são públicos, então sem elas o
       servidor montaria um quadro "válido" com a cédula do alvo e cédulas
       forjadas de valor conhecido, e obteria o voto por subtração.
    2. Checkpoint: o ``expected_checkpoint`` informado (fonte independente)
       ou, sem ele, o derivado do próprio arquivo (tamanho e hash do último
       registro). Neste caso, truncagem do fim ou um quadro alternativo
       inteiro NÃO são detectados: a autoridade confia no arquivo que lê.
    3. Cifras de cada registro em ``[2, p-1]``, no subgrupo e sem ``c1``
       repetido (``src.auditor.board_tally``, o mesmo código do auditor).
    4. Produto por candidato (``board_tally.aggregate_columns``) e nº de
       cédulas comparados com ``C1``, ``C2`` e ``ballot_count`` recebidos.

    Devolve o nº de cédulas do quadro. Qualquer falha lança
    ``AggregateVerificationError`` sem tocar em ``x_i``.
    """
    if ctx.candidates is None:
        raise AggregateVerificationError(
            "election.json sem a lista de candidatos: o agregado não pode ser conferido"
        )
    candidates = ctx.candidates
    voter_keys = _board_voter_keys(election_data)
    if not isinstance(board_path, (str, Path)) or not str(board_path):
        raise TypeError("board_path deve ser o caminho do quadro público (bulletin_board.jsonl)")
    path = Path(board_path)

    try:
        with open(path, "rb") as stream:
            records = list(read_records(stream))
    except OSError as exc:
        raise AggregateVerificationError(
            f"agregado recusado: quadro público ilegível ({path.name}: {exc.strerror or exc})"
        ) from None
    except Exception as exc:  # linha malformada: o leitor estrito recusa
        raise _board_invalid(exc) from None
    if not records:
        raise AggregateVerificationError(
            "agregado recusado: quadro público vazio, não há cédulas que justifiquem decifrar"
        )

    try:
        if expected_checkpoint is None:
            last = records[-1]
            checkpoint = make_checkpoint(
                election_id=ctx.election_id,
                size=len(records),
                head_hash=last.get("hash") if type(last) is dict else None,
            )
        else:
            checkpoint = expected_checkpoint
        verify_board(
            records,
            election_id=ctx.election_id,
            candidate_ids=candidates,
            voter_public_keys=voter_keys,
            expected_checkpoint=checkpoint,
        )
    except Exception as exc:  # BoardError, BallotError, chave malformada…: recusa (lado seguro)
        raise _board_invalid(exc) from None

    p, q, g = ctx.p, ctx.q, ctx.g
    seen_c1: dict[int, int] = {}
    ballots = []
    for position, record in enumerate(records):
        try:
            pairs = record_ciphertexts(record, candidates, p)
            register_ciphertexts(pairs, position, seen_c1, p=p, q=q)
        except BoardTallyError as exc:
            raise AggregateVerificationError(
                f"agregado recusado: quadro público inválido (entrada {position}: {exc})"
            ) from None
        ballots.append(pairs)
    recomputed = dict(zip(candidates, aggregate_columns(ballots, len(candidates), p=p, q=q, g=g)))
    board_count = len(records)

    problems = []
    if "ballot_count" not in aggregate_data:
        problems.append("ballot_count ausente")
    else:
        count = _parse_int(aggregate_data["ballot_count"], "ballot_count", AggregateVerificationError)
        if count != board_count:
            problems.append(f"ballot_count informado {count}, esperado {board_count}")
    for candidate_id in candidates:
        received, expected = aggregate[candidate_id], recomputed[candidate_id]
        differing = [name for name, a, b in zip(("C1", "C2"), received, expected) if a != b]
        if differing:
            problems.append(f"{' e '.join(differing)} de {candidate_id!r}")
    if problems:
        raise AggregateVerificationError(
            "agregado recusado: difere do recalculado a partir do quadro público "
            f"({board_count} cédula(s)): " + "; ".join(problems)
        )
    return board_count


# --------------------------------------------------------- Chaum-Pedersen
def _challenge(
    ctx: _ElectionContext,
    authority_id: str,
    candidate_id: str,
    h_i: int,
    c1: int,
    d: int,
    a1: int,
    a2: int,
) -> int:
    """Desafio Fiat-Shamir: ``c = SHA-256(contexto completo) mod q``.

    Incluir domínio, eleição, autoridade, candidato e grupo impede reaproveitar
    uma prova válida em outro contexto.
    """
    payload = _canonical_json(
        {
            "domain": PROOF_DOMAIN,
            "election_id": ctx.election_id,
            "authority_id": authority_id,
            "candidate_id": candidate_id,
            "p": str(ctx.p),
            "q": str(ctx.q),
            "g": str(ctx.g),
            "h_i": str(h_i),
            "c1": str(c1),
            "d": str(d),
            "a1": str(a1),
            "a2": str(a2),
        }
    )
    return int.from_bytes(hashlib.sha256(payload).digest(), "big") % ctx.q


def _prove_share(
    authority: Authority,
    ctx: _ElectionContext,
    candidate_id: str,
    c1: int,
    h_i: int,
) -> CandidatePartialShare:
    """Calcula ``d_i`` e a prova no processo da autoridade.

    ``x_i`` é lido pelo acesso interno do pacote ``src.authorities``
    (``Authority`` não o expõe publicamente) e, junto com ``w``, nunca sai
    desta função. Em caso de falha, a exceção é lançada FORA do bloco
    ``except``: assim ela não carrega a exceção original (cuja mensagem ou
    traceback poderiam conter valores secretos).
    """
    p, q, g = ctx.p, ctx.q, ctx.g
    failed = False
    try:
        x = authority._x  # acesso interno ao pacote; nunca exposto
        d = pow(c1, x, p)
        w = secrets.randbelow(q - 2) + 2  # efêmero, em [2, q-1], de fonte criptográfica
        a1 = pow(g, w, p)
        a2 = pow(c1, w, p)
        c = _challenge(ctx, authority.authority_id, candidate_id, h_i, c1, d, a1, a2)
        s = (w + c * x) % q
    except Exception:
        failed = True
    if failed:
        raise PartialDecryptionError(f"falha no cálculo local da parcela de {candidate_id!r}")
    return CandidatePartialShare(candidate_id, d, a1, a2, s)


def _verify_share(
    ctx: _ElectionContext,
    authority_id: str,
    h_i: int,
    candidate_id: str,
    c1: int,
    share: CandidatePartialShare,
) -> None:
    """Verifica uma parcela usando apenas dados públicos; lança ``InvalidShareError``."""
    p, q, g = ctx.p, ctx.q, ctx.g
    for name in ("d", "a1", "a2"):
        value = getattr(share, name)
        if type(value) is not int or not 2 <= value <= p - 1:
            raise InvalidShareError(f"{name} de {authority_id!r}/{candidate_id!r} fora de [2, p-1]")
    if type(share.s) is not int or not 0 <= share.s < q:
        raise InvalidShareError(f"s de {authority_id!r}/{candidate_id!r} fora de [0, q)")
    for name in ("d", "a1", "a2"):
        if pow(getattr(share, name), q, p) != 1:
            raise InvalidShareError(
                f"{name} de {authority_id!r}/{candidate_id!r} fora do subgrupo de ordem q"
            )

    c = _challenge(ctx, authority_id, candidate_id, h_i, c1, share.d, share.a1, share.a2)
    # g^s = g^(w + c·x) = a1 · h_i^c   e   C1^s = C1^(w + c·x) = a2 · d_i^c
    if pow(g, share.s, p) != share.a1 * pow(h_i, c, p) % p:
        raise InvalidShareError(f"prova de {authority_id!r}/{candidate_id!r} inválida (g^s)")
    if pow(c1, share.s, p) != share.a2 * pow(share.d, c, p) % p:
        raise InvalidShareError(f"prova de {authority_id!r}/{candidate_id!r} inválida (C1^s)")


# ---------------------------------------------------- lado da autoridade
def compute_authority_partials(
    authority: Authority,
    election_data: dict,
    aggregate_data: dict,
    *,
    board_path: Path | str,
    expected_checkpoint: dict | None = None,
    election_state: StateSource = None,
) -> AuthorityPartialSubmission:
    """Calcula, no processo da autoridade, as parcelas e provas de todos os candidatos.

    ``board_path`` (obrigatório, sem padrão) é o quadro público
    (``bulletin_board.jsonl``) que a AUTORIDADE lê para conferir o agregado
    recebido do servidor; ``expected_checkpoint`` é um checkpoint do quadro
    obtido de fonte independente, se houver (ver
    ``_verify_aggregate_against_board``).

    Ordem: ``election.json``, etapa, formato do agregado, chave local (mesmo
    grupo e mesmo ``h_i``) e, por fim, a conferência com o quadro. Só então
    ``x_i`` é usado. Lança ``AggregateVerificationError`` se o agregado não
    corresponder ao quadro. A submissão devolvida contém só dados públicos e é
    autoverificada.
    """
    if not isinstance(authority, Authority):
        raise TypeError("authority deve ser a instância local de Authority")
    ctx = _parse_election(election_data)
    _check_state(election_state)
    if ctx.candidates is None:
        raise AggregateVerificationError(
            "election.json sem a lista de candidatos: o agregado não pode ser conferido"
        )
    aggregate = _parse_aggregate(aggregate_data, ctx)

    group: GroupParams = authority.group
    if (group.p, group.q, group.g) != (ctx.p, ctx.q, ctx.g):
        raise PartialDecryptionError("a chave da autoridade foi gerada com outro grupo")
    public = authority.public_key()
    registered_h = ctx.authorities.get(public.authority_id)
    if registered_h is None:
        raise UnregisteredAuthorityError(f"autoridade {public.authority_id!r} não cadastrada")
    if registered_h != public.h:
        raise PartialDecryptionError("a chave local não corresponde à chave pública cadastrada")

    # Nada de x_i antes de o agregado conferir com o quadro público.
    _verify_aggregate_against_board(
        ctx, election_data, aggregate_data, aggregate, board_path, expected_checkpoint
    )

    shares = []
    for candidate_id in sorted(aggregate):
        c1, _ = aggregate[candidate_id]
        share = _prove_share(authority, ctx, candidate_id, c1, public.h)
        # Autoverificação: um cálculo defeituoso é detectado aqui, não no servidor.
        _verify_share(ctx, public.authority_id, public.h, candidate_id, c1, share)
        shares.append(share)
    return AuthorityPartialSubmission(public.authority_id, tuple(shares))


# ------------------------------------------------------- lado do servidor
class PartialDecryptionCollector:
    """Recebe e valida as submissões das autoridades no servidor.

    Contrato:
    - Exige cadastro congelado e, se ``election_state`` for informado (valor
      ou função como ``election.current_state``), etapa ``APURACAO`` a cada
      operação.
    - Uma submissão só é guardada depois que TODAS as suas parcelas foram
      verificadas; a primeira submissão de cada autoridade é preservada.
    - Nunca recebe objetos ``Authority`` nem chaves privadas.
    """

    def __init__(
        self,
        election_data: dict,
        aggregate_data: dict,
        *,
        election_state: StateSource = None,
    ) -> None:
        self._ctx = _parse_election(election_data)
        self._aggregate = _parse_aggregate(aggregate_data, self._ctx)
        self._state_source = election_state
        _check_state(self._state_source)
        self._submissions: dict[str, AuthorityPartialSubmission] = {}
        self._lock = threading.RLock()

    # -------------------------------------------------------------- consultas
    @property
    def election_id(self) -> str:
        return self._ctx.election_id

    @property
    def registered_authorities(self) -> tuple[str, ...]:
        return tuple(self._ctx.authorities)

    @property
    def candidate_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._aggregate))

    @property
    def submissions(self) -> tuple[AuthorityPartialSubmission, ...]:
        """Submissões aceitas, na ordem do cadastro das autoridades."""
        return tuple(
            self._submissions[a] for a in self._ctx.authorities if a in self._submissions
        )

    @property
    def missing_authorities(self) -> tuple[str, ...]:
        return tuple(a for a in self._ctx.authorities if a not in self._submissions)

    @property
    def is_complete(self) -> bool:
        return not self.missing_authorities

    # ---------------------------------------------------------------- envio
    def submit(self, submission: AuthorityPartialSubmission) -> None:
        """Valida e registra a submissão de uma autoridade.

        Lança ``TallyStateError``, ``InvalidShareError``,
        ``UnregisteredAuthorityError`` ou ``DuplicateShareError``.
        """
        with self._lock:
            _check_state(self._state_source)
            if type(submission) is not AuthorityPartialSubmission:
                raise InvalidShareError("submission deve ser AuthorityPartialSubmission")
            authority_id = submission.authority_id
            try:
                validate_authority_id(authority_id)
            except ValueError:
                raise InvalidShareError("authority_id inválido") from None
            # A chave usada na verificação vem SEMPRE de election.json, nunca
            # da submissão.
            h_i = self._ctx.authorities.get(authority_id)
            if h_i is None:
                raise UnregisteredAuthorityError(f"autoridade {authority_id!r} não cadastrada")
            if authority_id in self._submissions:
                raise DuplicateShareError(f"autoridade {authority_id!r} já enviou sua parcela")

            expected = set(self._aggregate)
            received = set(submission.candidate_ids)
            if received != expected:
                raise InvalidShareError(
                    f"candidatos divergentes: faltando {sorted(expected - received)}, "
                    f"sobrando {sorted(received - expected)}"
                )
            for share in submission.shares:
                c1, _ = self._aggregate[share.candidate_id]
                _verify_share(self._ctx, authority_id, h_i, share.candidate_id, c1, share)
            self._submissions[authority_id] = submission

    # ----------------------------------------------------------- persistência
    def to_dict(self) -> dict:
        return {
            "schema_version": PARTIALS_SCHEMA_VERSION,
            "election_id": self._ctx.election_id,
            "partials": [s.to_dict() for s in self.submissions],
        }

    def save(self, path: Path | str = DEFAULT_PARTIALS_PATH) -> dict:
        """Grava ``authority_partials.json`` atomicamente (também parcial)."""
        with self._lock:
            data = self.to_dict()
            _atomic_write_json(Path(path), data)
            return data

    @classmethod
    def load(
        cls,
        election_data: dict,
        aggregate_data: dict,
        path: Path | str = DEFAULT_PARTIALS_PATH,
        *,
        election_state: StateSource = None,
    ) -> "PartialDecryptionCollector":
        """Carrega ``authority_partials.json`` REVERIFICANDO cada submissão.

        O arquivo é público e pode ter sido adulterado: nada é aceito sem
        passar de novo por ``submit``.
        """
        collector = cls(election_data, aggregate_data, election_state=election_state)
        data = load_public_json(path)
        if data.get("election_id") != collector.election_id:
            raise PartialDecryptionError(f"{path} pertence a outra eleição")
        partials = data.get("partials")
        if not isinstance(partials, list):
            raise PartialDecryptionError(f"{path} sem a lista de parcelas")
        for raw in partials:
            collector.submit(AuthorityPartialSubmission.from_dict(raw))
        return collector


def verify_authority_partials(
    submission: AuthorityPartialSubmission,
    election_data: dict,
    aggregate_data: dict,
    *,
    election_state: StateSource = None,
) -> None:
    """Verifica uma submissão isolada (mesmas regras de ``submit``)."""
    collector = PartialDecryptionCollector(
        election_data, aggregate_data, election_state=election_state
    )
    collector.submit(submission)


# ------------------------------------------------- combinação e resultado
def combine_and_decrypt_result(
    election_data: dict,
    aggregate_data: dict,
    submissions: PartialDecryptionCollector | Iterable[AuthorityPartialSubmission],
    *,
    max_votes: int | None = None,
    election_state: StateSource = None,
    result_path: Path | str = DEFAULT_RESULT_PATH,
    mod_inv: ModInv | None = None,
    discrete_log: DiscreteLog | None = None,
) -> dict:
    """Combina as parcelas de TODAS as autoridades e publica ``result.json``.

    As submissões são sempre reverificadas aqui (mesmo vindas de um coletor),
    para que um resultado nunca dependa de dados não verificados.

    ``max_votes`` (limite de cada total) é, por padrão, o nº de cédulas
    (``ballot_count`` do agregado), o mesmo critério do auditor. Um valor
    explícito pode ser menor, nunca maior que o nº de cédulas.

    Lança ``MissingAuthorityShareError`` se faltar qualquer autoridade
    cadastrada (mesmo havendo 3 ou mais), ``DecryptionError`` se algum total
    não estiver em ``[0, max_votes]`` e ``InconsistentTotalsError`` (subclasse
    de ``DecryptionError``) se a soma dos totais diferir do nº de cédulas. Em
    qualquer falha, nada é gravado.
    """
    mod_inv_fn = _resolve(mod_inv, _default_mod_inv, "mod_inv")

    if isinstance(submissions, PartialDecryptionCollector):
        submissions = submissions.submissions
    collector = PartialDecryptionCollector(
        election_data, aggregate_data, election_state=election_state
    )
    for submission in submissions:
        collector.submit(submission)

    # Todas as cadastradas, não apenas MIN_AUTHORITIES: h = Π h_i inclui
    # todas, então todas as parcelas são necessárias para cancelar h^R.
    missing = collector.missing_authorities
    if missing:
        raise MissingAuthorityShareError(f"faltam parcelas das autoridades {list(missing)}")

    ctx = collector._ctx
    # Sem injeção, a busca limitada é a de src.crypto.elgamal, no grupo da eleição.
    discrete_log_fn = _resolve(discrete_log, crypto_discrete_log(ctx.q), "discrete_log")
    # Limite = nº de cédulas aceitas (critério do auditor), não nº de eleitores.
    ballot_count = _aggregate_ballot_count(aggregate_data, ctx)
    if max_votes is None:
        max_votes = ballot_count
    if type(max_votes) is not int or max_votes < 0:
        raise PartialDecryptionError("max_votes deve ser um inteiro >= 0")
    if max_votes > ballot_count:
        raise PartialDecryptionError(
            f"max_votes ({max_votes}) maior que o número de cédulas ({ballot_count})"
        )

    p, g = ctx.p, ctx.g
    totals: dict[str, int] = {}
    for candidate_id in collector.candidate_ids:
        _, c2 = collector._aggregate[candidate_id]

        # D = Π d_i = C1^(Σ x_i) = h^R
        combined = 1
        for submission in collector.submissions:
            combined = combined * submission.share_for(candidate_id).d % p

        try:
            inverse = mod_inv_fn(combined, p)
        except Exception:
            inverse = None
        if type(inverse) is not int or combined * inverse % p != 1:
            raise DecryptionError(f"inverso modular inválido para {candidate_id!r}")
        message = c2 * inverse % p  # M = g^T

        try:
            tally = discrete_log_fn(message, g, p, max_votes)
        except Exception:
            tally = None
        # Conferência barata do resultado delegado: g^tally ≡ M e 0 <= tally <= max.
        if (
            type(tally) is not int
            or not 0 <= tally <= max_votes
            or pow(g, tally, p) != message
        ):
            raise DecryptionError(f"total de {candidate_id!r} fora de [0, {max_votes}]")
        totals[candidate_id] = tally

    # Cada total isolado cabe em [0, max_votes]; agora o conjunto precisa
    # somar exatamente o nº de cédulas (sem voto em branco: ver a função).
    _check_totals_sum(totals, ballot_count)

    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "election_id": ctx.election_id,
        "totals": totals,
        "authorities": list(collector.registered_authorities),
        "max_votes": max_votes,
    }
    _atomic_write_json(Path(result_path), result)
    return result