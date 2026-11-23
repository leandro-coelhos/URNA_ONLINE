"""Decifração conjunta do resultado: parcelas das autoridades.

O que este módulo FAZ
---------------------
- Lado da autoridade: ``compute_authority_partials`` calcula ``d_i`` e a
  prova de cada candidato, no processo local, a partir de ``Authority``.
- Lado do servidor: ``PartialDecryptionCollector`` (e o atalho
  ``verify_authority_partials``) aceita somente submissões de autoridades
  cadastradas, sem duplicidade, cobrindo exatamente os candidatos da cifra
  agregada e com provas válidas contra o ``h_i`` de ``election.json``.
- ``combine_and_decrypt_result`` exige TODAS as autoridades cadastradas,
  combina as parcelas, recupera os totais e publica ``result.json``.
- Persiste ``authority_partials.json`` e ``result.json`` de forma atômica
  (``mkstemp`` + ``os.replace``), com inteiros grandes como strings decimais.

O que este módulo NÃO FAZ
-------------------------
- Não agrega as cédulas (``server/tally.py``) nem muda a etapa da eleição.
- Nunca grava, devolve ou inclui em exceções ``x_i`` ou o valor efêmero
  ``w``. As estruturas de submissão carregam apenas dados públicos.
- Não garante que cada voto cifrado seja 0 ou 1: apenas limita cada total a ``max_votes``.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import secrets
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Union

from src.authorities.authority import (
    MIN_AUTHORITIES,
    Authority,
    GroupParams,
    _atomic_write_json,  # escrita atômica do próprio pacote (mkstemp + os.replace)
    validate_authority_id,
)
from src.election.states import ElectionState

# Importação defensiva: sem src/crypto nesta branch, as funções podem ser
# injetadas. NÃO há implementação local de reserva.
try:
    from src.crypto.group import mod_exp as _default_mod_exp
except ImportError:  # pragma: no cover - depende da branch
    _default_mod_exp = None


def _optional_import(attr: str, modules: tuple[str, ...]) -> Callable | None:
    """Primeiro ``attr`` chamável encontrado em ``modules``, ou ``None``."""
    for module_name in modules:
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        value = getattr(module, attr, None)
        if callable(value):
            return value
    return None


_default_mod_inv = _optional_import("mod_inv", ("src.crypto.group",))
_default_discrete_log = _optional_import(
    "discrete_log", ("src.crypto.elgamal", "src.crypto.homomorphic", "src.crypto.group")
)

__all__ = [
    "DEFAULT_AGGREGATE_PATH",
    "DEFAULT_ELECTION_PATH",
    "DEFAULT_PARTIALS_PATH",
    "DEFAULT_RESULT_PATH",
    "PROOF_DOMAIN",
    "AuthorityPartialSubmission",
    "CandidatePartialShare",
    "DecryptionError",
    "DuplicateShareError",
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
RESULT_SCHEMA_VERSION = 1
MAX_CANDIDATE_ID = 128

# Contratos das funções delegadas ao módulo de crypto:
#   mod_exp(base, exp, mod) -> int
#   mod_inv(value, mod) -> int                       (value · resultado ≡ 1 mod p)
#   discrete_log(target, base, mod, max_exp) -> int | None
#                                                    (menor t em [0, max_exp] com base^t ≡ target)
# Se a interface real for outra, injete um adaptador.
ModExp = Callable[[int, int, int], int]
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


def _parse_election(data: object, mod_exp: ModExp) -> _ElectionContext:
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
        or mod_exp(g, q, p) != 1
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
        if not 1 < h_i < p - 1 or mod_exp(h_i, q, p) != 1:
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


def _parse_aggregate(
    data: object, ctx: _ElectionContext, mod_exp: ModExp
) -> MappingProxyType:
    """Valida ``aggregate_ciphertexts.json``: ``candidate_id -> (C1, C2)``."""
    if type(data) is not dict:
        raise PartialDecryptionError("aggregate_ciphertexts.json deve conter um objeto JSON")
    if data.get("election_id") != ctx.election_id:
        raise PartialDecryptionError("as cifras agregadas pertencem a outra eleição")
    raw = data.get("ciphertexts")
    if type(raw) is not dict or not raw:
        raise PartialDecryptionError("ciphertexts deve ser um objeto não vazio")
    if ctx.candidates is not None and set(raw) != set(ctx.candidates):
        raise PartialDecryptionError("candidatos das cifras agregadas diferem dos da eleição")

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
            if not 2 <= value <= p - 1 or mod_exp(value, q, p) != 1:
                raise PartialDecryptionError(
                    f"{name} de {candidate_id!r} fora de [2, p-1] ou do subgrupo de ordem q"
                )
            pair.append(value)
        parsed[candidate_id] = (pair[0], pair[1])
    return MappingProxyType(parsed)


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
    mod_exp: ModExp,
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
        d = mod_exp(c1, x, p)
        w = secrets.randbelow(q - 2) + 2  # efêmero, em [2, q-1], de fonte criptográfica
        a1 = mod_exp(g, w, p)
        a2 = mod_exp(c1, w, p)
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
    mod_exp: ModExp,
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
        if mod_exp(getattr(share, name), q, p) != 1:
            raise InvalidShareError(
                f"{name} de {authority_id!r}/{candidate_id!r} fora do subgrupo de ordem q"
            )

    c = _challenge(ctx, authority_id, candidate_id, h_i, c1, share.d, share.a1, share.a2)
    # g^s = g^(w + c·x) = a1 · h_i^c   e   C1^s = C1^(w + c·x) = a2 · d_i^c
    if mod_exp(g, share.s, p) != share.a1 * mod_exp(h_i, c, p) % p:
        raise InvalidShareError(f"prova de {authority_id!r}/{candidate_id!r} inválida (g^s)")
    if mod_exp(c1, share.s, p) != share.a2 * mod_exp(share.d, c, p) % p:
        raise InvalidShareError(f"prova de {authority_id!r}/{candidate_id!r} inválida (C1^s)")


# ---------------------------------------------------- lado da autoridade
def compute_authority_partials(
    authority: Authority,
    election_data: dict,
    aggregate_data: dict,
    *,
    election_state: StateSource = None,
    mod_exp: ModExp | None = None,
) -> AuthorityPartialSubmission:
    """Calcula, no processo da autoridade, as parcelas e provas de todos os candidatos.

    Confere antes que a chave local corresponde à cadastrada (mesmo grupo e
    mesmo ``h_i``): parcelas de uma chave errada fariam a apuração falhar.
    A submissão devolvida contém só dados públicos e é autoverificada.
    """
    if not isinstance(authority, Authority):
        raise TypeError("authority deve ser a instância local de Authority")
    mod_exp_fn = _resolve(mod_exp, _default_mod_exp, "mod_exp")
    ctx = _parse_election(election_data, mod_exp_fn)
    _check_state(election_state)
    aggregate = _parse_aggregate(aggregate_data, ctx, mod_exp_fn)

    group: GroupParams = authority.group
    if (group.p, group.q, group.g) != (ctx.p, ctx.q, ctx.g):
        raise PartialDecryptionError("a chave da autoridade foi gerada com outro grupo")
    public = authority.public_key()
    registered_h = ctx.authorities.get(public.authority_id)
    if registered_h is None:
        raise UnregisteredAuthorityError(f"autoridade {public.authority_id!r} não cadastrada")
    if registered_h != public.h:
        raise PartialDecryptionError("a chave local não corresponde à chave pública cadastrada")

    shares = []
    for candidate_id in sorted(aggregate):
        c1, _ = aggregate[candidate_id]
        share = _prove_share(authority, ctx, candidate_id, c1, public.h, mod_exp_fn)
        # Autoverificação: um mod_exp defeituoso é detectado aqui, não no servidor.
        _verify_share(ctx, public.authority_id, public.h, candidate_id, c1, share, mod_exp_fn)
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
        mod_exp: ModExp | None = None,
    ) -> None:
        self._mod_exp = _resolve(mod_exp, _default_mod_exp, "mod_exp")
        self._ctx = _parse_election(election_data, self._mod_exp)
        self._aggregate = _parse_aggregate(aggregate_data, self._ctx, self._mod_exp)
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
                _verify_share(self._ctx, authority_id, h_i, share.candidate_id, c1, share,
                              self._mod_exp)
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
        mod_exp: ModExp | None = None,
    ) -> "PartialDecryptionCollector":
        """Carrega ``authority_partials.json`` REVERIFICANDO cada submissão.

        O arquivo é público e pode ter sido adulterado: nada é aceito sem
        passar de novo por ``submit``.
        """
        collector = cls(election_data, aggregate_data, election_state=election_state,
                        mod_exp=mod_exp)
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
    mod_exp: ModExp | None = None,
) -> None:
    """Verifica uma submissão isolada (mesmas regras de ``submit``)."""
    collector = PartialDecryptionCollector(
        election_data, aggregate_data, election_state=election_state, mod_exp=mod_exp
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
    mod_exp: ModExp | None = None,
    mod_inv: ModInv | None = None,
    discrete_log: DiscreteLog | None = None,
) -> dict:
    """Combina as parcelas de TODAS as autoridades e publica ``result.json``.

    As submissões são sempre reverificadas aqui (mesmo vindas de um coletor),
    para que um resultado nunca dependa de dados não verificados.

    Lança ``MissingAuthorityShareError`` se faltar qualquer autoridade
    cadastrada (mesmo havendo 3 ou mais) e ``DecryptionError`` se algum total
    não estiver em ``[0, max_votes]``. Em qualquer falha, nada é gravado.
    """
    mod_exp_fn = _resolve(mod_exp, _default_mod_exp, "mod_exp")
    mod_inv_fn = _resolve(mod_inv, _default_mod_inv, "mod_inv")
    discrete_log_fn = _resolve(discrete_log, _default_discrete_log, "discrete_log")

    if isinstance(submissions, PartialDecryptionCollector):
        submissions = submissions.submissions
    collector = PartialDecryptionCollector(
        election_data, aggregate_data, election_state=election_state, mod_exp=mod_exp_fn
    )
    for submission in submissions:
        collector.submit(submission)

    # Todas as cadastradas, não apenas MIN_AUTHORITIES: h = Π h_i inclui
    # todas, então todas as parcelas são necessárias para cancelar h^R.
    missing = collector.missing_authorities
    if missing:
        raise MissingAuthorityShareError(f"faltam parcelas das autoridades {list(missing)}")

    ctx = collector._ctx
    if max_votes is None:
        if ctx.voter_count is None:
            raise PartialDecryptionError("informe max_votes: election.json não lista os eleitores")
        max_votes = ctx.voter_count
    if type(max_votes) is not int or max_votes < 0:
        raise PartialDecryptionError("max_votes deve ser um inteiro >= 0")

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
            or mod_exp_fn(g, tally, p) != message
        ):
            raise DecryptionError(f"total de {candidate_id!r} fora de [0, {max_votes}]")
        totals[candidate_id] = tally

    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "election_id": ctx.election_id,
        "totals": totals,
        "authorities": list(collector.registered_authorities),
        "max_votes": max_votes,
    }
    _atomic_write_json(Path(result_path), result)
    return result