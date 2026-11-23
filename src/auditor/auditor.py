"""Auditor independente da eleição.

O auditor recebe SOMENTE o diretório público da eleição (``data/public/``) e
responde a uma pergunta: os dados publicados formam uma eleição válida ou
houve adulteração? Ele não confia no servidor: recalcula tudo o que pode a
partir dos arquivos e compara com o que foi publicado.

Arquivos lidos (todos em ``public_dir``)::

    election.json               grupo, autoridades (h_i), h, candidatos, eleitores
    voters.json                 opcional; se existir, precisa coincidir com election.json
    bulletin_board.jsonl        quadro público REAL (src.bulletin_board), um registro por linha
    aggregate_ciphertexts.json  produto homomórfico publicado, por candidato
    authority_partials.json     parcelas d_i e provas de Chaum-Pedersen
    result.json                 totais publicados

Formato do quadro (``src.bulletin_board.hash_chain``)::

    {"schema_version": 1, "index": i, "previous_hash": "<hex>",
     "ballot": {"schema_version": 1, "election_id": ..., "voter_id": ...,
                "ciphertexts": [{"candidate_id": ..., "c1": "<dec>", "c2": "<dec>"}, ...]},
     "signature": "<Base64>", "hash": "<hex>"}

Verificações, na ordem do relatório
-----------------------------------
0. Dados públicos: ``election.json`` coerente (cadastro congelado, grupo
   válido, pelo menos 3 autoridades no subgrupo, ``h = Π h_i``, candidatos,
   eleitores) e ``voters.json`` igual ao cadastro de ``election.json``.
a) Cadeia de hashes: cada linha é lida com o leitor estrito de
   ``hash_chain.read_records`` (sem JSON ambíguo); para cada registro ``i``,
   ``index == i``, ``previous_hash`` = hash gravado no registro ``i-1`` (ou
   ``hash_chain.genesis_hash(election_id)``) e ``hash`` =
   ``hash_chain.hash_record`` do registro sem o campo ``hash``. Detecta
   alteração, remoção, reordenação e registros fora do formato. A remoção do
   ÚLTIMO registro não quebra a cadeia; ela é detectada em (d) e (e), pois o
   produto homomórfico muda.
b) Elegibilidade e unicidade: todo ``ballot.voter_id`` do quadro está
   cadastrado e aparece uma única vez.
c) Assinaturas e cifras: a assinatura de cada registro é verificada com
   ``src.crypto.ballots.verify_signed_ballot`` e a chave CADASTRADA do eleitor
   (nunca uma chave do próprio registro), o que também confere eleição,
   candidatos e ordem; cada cifra está em ``[2, p-1]`` e no subgrupo de ordem
   ``q`` e nenhum ``c1`` se repete.
d) Agregação homomórfica: ``Π c1`` e ``Π c2`` por candidato, recalculados do
   quadro com ``src.crypto.homomorphic.aggregate_ciphertexts``, são iguais aos
   de ``aggregate_ciphertexts.json``.
e) Apuração: as provas de Chaum-Pedersen de ``authority_partials.json`` são
   reverificadas contra o agregado RECALCULADO (não o publicado), todas as
   autoridades participaram e, para cada candidato, ``C2 ≡ g^T · Π d_i
   (mod p)``, em que ``T`` é o total de ``result.json``. Conferir é mais
   barato que decifrar: não é preciso calcular o logaritmo discreto. Cada
   total precisa estar em ``[0, nº de cédulas do quadro]`` e a soma dos
   totais precisa ser IGUAL ao nº de cédulas (não há voto em branco: cada
   cédula honesta cifra exatamente um 1; ver ``_check_totals_sum``).

Todas as verificações rodam mesmo quando uma anterior falha, para que o
relatório aponte todos os problemas de uma vez. Nenhuma entrada malformada
derruba o auditor: vira uma falha com o motivo.

O que este módulo NÃO FAZ
-------------------------
- Importa SOMENTE de ``src.crypto`` e ``src.bulletin_board``: nada de
  ``src.server``, ``src.election`` nem ``src.authorities``. Não há estado do
  servidor aqui.
- Não lê ``data/private/`` nem qualquer chave privada; só abre os arquivos
  acima, dentro de ``public_dir``.
- Não reimplementa primitivas: formato e assinatura da cédula vêm de
  ``src.crypto.ballots``; hash, elo inicial e leitura do quadro, de
  ``src.bulletin_board.hash_chain``; produto homomórfico, de
  ``src.crypto.homomorphic``. A leitura das cifras de cada registro, a
  checagem de subgrupo/``c1`` repetido e o produto por candidato ficam em
  ``src.auditor.board_tally``, o mesmo código que cada autoridade usa para
  conferir o agregado antes de decifrar (ela importa só esse módulo, nunca
  ``Auditor``). A exponenciação modular é o ``pow`` nativo do
  Python (padrão do projeto). A verificação da prova de
  Chaum-Pedersen das autoridades é refeita aqui, a partir do protocolo público
  (domínio ``URNA_ONLINE/chaum-pedersen/v1``), para que o auditor não dependa
  do código das autoridades; um teste garante que ela coincide com a de
  ``src.authorities.partial_decryption``.
- Não usa um checkpoint confiável do quadro: sem uma fonte independente do
  tamanho e do hash final, a remoção do último registro antes da apuração é
  indistinguível de uma abstenção (limitação documentada, cenário 4c da T14).
- Não verifica prova de validade 0/1 (ZKP): o formato da cédula e do quadro
  não tem campo para ela. Garante só que cada total está em
  ``[0, número de cédulas]`` e que a soma dos totais é o número de cédulas.
  Essa soma é uma detecção AGREGADA: acusa que alguma cédula não cifra
  exatamente um voto (ex.: ``m = 2``, ou 1 para os dois candidatos), sem
  dizer qual; cédulas que mantêm a soma 1 (ex.: ``m = -1`` e ``m = 2``)
  continuam indetectáveis sem a prova 0/1.
- Não escreve arquivos e não muda a etapa da eleição: quem chama decide o que
  fazer com o relatório (por exemplo, ``Election.mark_audited()``).
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from src.bulletin_board.hash_chain import BoardError, genesis_hash, hash_record, read_records
from src.crypto.ballots import BallotError, InvalidBallotSignatureError, verify_signed_ballot

# Import relativo ao próprio pacote: board_tally também só importa src.crypto
# (o teste AST do auditor confere todos os arquivos de src/auditor/).
from .board_tally import (
    BoardTallyError,
    aggregate_columns,
    parse_decimal,
    record_ciphertexts,
    register_ciphertexts,
)


__all__ = [
    "AGGREGATE_FILE",
    "BOARD_FILE",
    "CHECK_AGGREGATE",
    "CHECK_ELIGIBILITY",
    "CHECK_HASH_CHAIN",
    "CHECK_NAMES",
    "CHECK_PUBLIC_DATA",
    "CHECK_RESULT",
    "CHECK_SIGNATURES",
    "DEFAULT_PUBLIC_DIR",
    "ELECTION_FILE",
    "PARTIALS_FILE",
    "PROOF_DOMAIN",
    "RESULT_FILE",
    "VOTERS_FILE",
    "AuditReport",
    "Auditor",
    "CheckResult",
    "audit_election",
    "main",
]

DEFAULT_PUBLIC_DIR = Path("data/public")
ELECTION_FILE = "election.json"
VOTERS_FILE = "voters.json"
BOARD_FILE = "bulletin_board.jsonl"
AGGREGATE_FILE = "aggregate_ciphertexts.json"
PARTIALS_FILE = "authority_partials.json"
RESULT_FILE = "result.json"

CHECK_PUBLIC_DATA = "public_data"
CHECK_HASH_CHAIN = "hash_chain"
CHECK_ELIGIBILITY = "eligibility_uniqueness"
CHECK_SIGNATURES = "signatures_proofs"
CHECK_AGGREGATE = "homomorphic_aggregate"
CHECK_RESULT = "tally_result"
CHECK_NAMES = (
    CHECK_PUBLIC_DATA,
    CHECK_HASH_CHAIN,
    CHECK_ELIGIBILITY,
    CHECK_SIGNATURES,
    CHECK_AGGREGATE,
    CHECK_RESULT,
)
_DESCRIPTIONS = MappingProxyType(
    {
        CHECK_PUBLIC_DATA: "Dados públicos (election.json / voters.json)",
        CHECK_HASH_CHAIN: "a) Cadeia de hashes do quadro público",
        CHECK_ELIGIBILITY: "b) Elegibilidade e unicidade dos eleitores",
        CHECK_SIGNATURES: "c) Assinaturas e cifras das cédulas",
        CHECK_AGGREGATE: "d) Produto homomórfico das cifras",
        CHECK_RESULT: "e) Parcelas das autoridades e resultado",
    }
)

# Protocolo público das parcelas (o mesmo de src.authorities.partial_decryption).
PROOF_DOMAIN = "URNA_ONLINE/chaum-pedersen/v1"
MIN_AUTHORITIES = 3
MIN_CANDIDATES = 2
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


# --------------------------------------------------------------------- relatório
@dataclass(frozen=True)
class CheckResult:
    """Resultado de UMA verificação: aprovada ou a lista exata de motivos."""

    name: str
    description: str
    errors: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "passed": self.passed,
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class AuditReport:
    """Relatório completo. A eleição é válida só se TODAS as verificações passarem."""

    election_id: str | None
    checks: tuple[CheckResult, ...]

    @property
    def valid(self) -> bool:
        return all(check.passed for check in self.checks)

    @property
    def failures(self) -> tuple[CheckResult, ...]:
        return tuple(check for check in self.checks if not check.passed)

    @property
    def errors(self) -> tuple[str, ...]:
        return tuple(f"[{c.name}] {e}" for c in self.checks for e in c.errors)

    def check(self, name: str) -> CheckResult:
        for check in self.checks:
            if check.name == name:
                return check
        raise KeyError(name)

    def to_dict(self) -> dict:
        return {
            "election_id": self.election_id,
            "valid": self.valid,
            "checks": [check.to_dict() for check in self.checks],
        }

    def format(self) -> str:
        """Texto para o terminal (``python -m src.auditor.auditor``).

        Uma linha por verificação e cada motivo de falha.
        """
        title = self.election_id if self.election_id is not None else "?"
        lines = [f"Auditoria da eleição {title!r}"]
        for check in self.checks:
            lines.append(f"  [{'OK' if check.passed else 'FALHA':5}] {check.description}")
            lines.extend(f"          - {error}" for error in check.errors)
        verdict = "ELEIÇÃO VÁLIDA" if self.valid else "ELEIÇÃO INVÁLIDA (dados adulterados ou inconsistentes)"
        lines.append(f"Resultado: {verdict}")
        return "\n".join(lines)

    __str__ = format


class _AuditError(Exception):
    """Falha pontual com mensagem já pronta para o relatório."""


# -------------------------------------------------------------- dados públicos
@dataclass(frozen=True)
class _Group:
    """Parâmetros do grupo lidos de ``election.json``."""

    p: int
    q: int
    g: int


@dataclass(frozen=True)
class _PublicContext:
    election_id: str
    group: _Group
    joint_public_key: int
    candidates: tuple[str, ...]
    voters: Mapping[str, str]  # voter_id -> chave pública cadastrada
    authorities: Mapping[str, int]  # authority_id -> h_i, na ordem do cadastro


@dataclass(frozen=True)
class _BoardEntry:
    """Uma linha do quadro: ``record`` é ``None`` se a linha for ilegível."""

    line_no: int
    record: dict | None


def _parse_int(value: object, what: str) -> int:
    """``int`` estrito ou string decimal canônica (formato dos JSON públicos)."""
    try:
        return parse_decimal(value, what)
    except BoardTallyError as exc:
        raise _AuditError(str(exc)) from None


def _is_identifier(value: object) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _parse_voter_list(raw: object, source: str) -> dict[str, str]:
    if not isinstance(raw, list) or not raw:
        raise _AuditError(f"{source}: lista de eleitores ausente ou vazia")
    voters: dict[str, str] = {}
    for entry in raw:
        if type(entry) is not dict:
            raise _AuditError(f"{source}: registro de eleitor malformado")
        voter_id = entry.get("voter_id")
        if not _is_identifier(voter_id):
            raise _AuditError(f"{source}: voter_id inválido: {voter_id!r}")
        # "public_key_pem" é o nome de Registration.export_public_data().
        key = entry.get("public_key", entry.get("public_key_pem"))
        if not isinstance(key, str) or not key.strip():
            raise _AuditError(f"{source}: chave pública do eleitor {voter_id!r} ausente")
        if "PRIVATE KEY" in key:
            raise _AuditError(f"{source}: o eleitor {voter_id!r} tem chave PRIVADA publicada")
        if voter_id in voters:
            raise _AuditError(f"{source}: eleitor {voter_id!r} repetido no cadastro")
        voters[voter_id] = key
    return voters


def _record_voter(record: dict) -> object:
    ballot = record.get("ballot")
    return ballot.get("voter_id") if type(ballot) is dict else None


# ----------------------------------------------------------------------- auditor
class Auditor:
    """Audita uma eleição a partir apenas de ``public_dir``.

    Uso::

        report = Auditor("data/public").run()
        print(report.format())
        if report.valid:
            ...

    Contrato:
    - Lê somente os seis arquivos públicos de ``public_dir``; nunca escreve.
    - A chave usada em cada assinatura vem do cadastro publicado, nunca do
      registro do quadro.
    - ``run()`` nunca lança por causa de dados malformados: cada problema vira
      um motivo de falha no relatório.
    - A assinatura é SEMPRE verificada com ``src.crypto.ballots``; não há como
      desativar essa verificação.
    """

    def __init__(self, public_dir: Path | str = DEFAULT_PUBLIC_DIR) -> None:
        self._public_dir = Path(public_dir)
        # Sem verificar assinaturas não há auditoria: não existe modo "vazio".
        verifier = verify_signed_ballot
        if not callable(verifier):
            raise RuntimeError("verify_signed_ballot (src.crypto.ballots) indisponível")
        self._verify_ballot = verifier

    @property
    def public_dir(self) -> Path:
        return self._public_dir

    # ------------------------------------------------------------------ leitura
    def _path(self, name: str) -> Path:
        return self._public_dir / name

    def _read_bytes(self, name: str) -> bytes:
        path = self._path(name)
        try:
            with open(path, "rb") as fh:
                return fh.read()
        except FileNotFoundError:
            raise _AuditError(f"{name} não encontrado em {self._public_dir}") from None
        except OSError as exc:
            raise _AuditError(f"{name} ilegível: {exc}") from None

    def _read_json(self, name: str) -> Any:
        try:
            return json.loads(self._read_bytes(name).decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise _AuditError(f"{name} não é JSON válido: {exc}") from None

    def _read_json_object(self, name: str) -> dict:
        data = self._read_json(name)
        if type(data) is not dict:
            raise _AuditError(f"{name} não contém um objeto JSON")
        return data

    # --------------------------------------------------------------- execução
    def run(self) -> AuditReport:
        """Executa todas as verificações e devolve o relatório."""
        public_errors: list[str] = []
        ctx = self._guard(public_errors, self._load_public_context)
        results = [self._result(CHECK_PUBLIC_DATA, public_errors)]

        if ctx is None:
            reason = "não executada: os dados públicos da eleição são inválidos"
            results.extend(self._result(name, [reason]) for name in CHECK_NAMES[1:])
            return AuditReport(self._guess_election_id(), tuple(results))

        board_errors: list[str] = []
        entries = self._guard(board_errors, self._load_board) or []

        chain_errors = list(board_errors)
        self._guard(chain_errors, self._check_hash_chain, ctx, entries)
        results.append(self._result(CHECK_HASH_CHAIN, chain_errors))

        eligibility_errors: list[str] = []
        self._guard(eligibility_errors, self._check_eligibility, ctx, entries)
        results.append(self._result(CHECK_ELIGIBILITY, eligibility_errors))

        signature_errors: list[str] = []
        self._guard(signature_errors, self._check_signatures, ctx, entries)
        results.append(self._result(CHECK_SIGNATURES, signature_errors))

        aggregate_errors: list[str] = []
        recomputed = self._guard(aggregate_errors, self._check_aggregate, ctx, entries)
        results.append(self._result(CHECK_AGGREGATE, aggregate_errors))

        result_errors: list[str] = []
        if recomputed is None:
            result_errors.append("não executada: o produto homomórfico não pôde ser recalculado")
        else:
            self._guard(result_errors, self._check_result, ctx, entries, recomputed)
        results.append(self._result(CHECK_RESULT, result_errors))

        return AuditReport(ctx.election_id, tuple(results))

    @staticmethod
    def _result(name: str, errors: Sequence[str]) -> CheckResult:
        return CheckResult(name, _DESCRIPTIONS[name], tuple(errors))

    @staticmethod
    def _guard(errors: list[str], function: Callable, *args: Any) -> Any:
        """Roda uma verificação; falhas viram motivos, nunca exceções para fora."""
        try:
            return function(errors, *args)
        except _AuditError as exc:
            errors.append(str(exc))
        except Exception as exc:  # dados hostis não podem derrubar o auditor
            errors.append(f"erro inesperado ({type(exc).__name__}): {exc}")
        return None

    def _guess_election_id(self) -> str | None:
        try:
            value = self._read_json_object(ELECTION_FILE).get("election_id")
        except _AuditError:
            return None
        return value if _is_identifier(value) else None

    # --------------------------------------------------- 0. dados públicos
    def _load_public_context(self, errors: list[str]) -> _PublicContext | None:
        data = self._read_json_object(ELECTION_FILE)

        election_id = data.get("election_id")
        if not _is_identifier(election_id):
            raise _AuditError(f"{ELECTION_FILE}: election_id inválido")
        if data.get("frozen") is not True:
            errors.append(f"{ELECTION_FILE}: o cadastro não foi publicado como congelado")

        group = self._parse_group(data.get("group"))
        p, q = group.p, group.q

        raw = data.get("authorities")
        if not isinstance(raw, list) or len(raw) < MIN_AUTHORITIES:
            raise _AuditError(
                f"{ELECTION_FILE}: autoridades inválidas: são exigidas pelo menos "
                f"{MIN_AUTHORITIES}"
            )
        authorities: dict[str, int] = {}
        joint = 1
        for entry in raw:
            if type(entry) is not dict:
                raise _AuditError(f"{ELECTION_FILE}: autoridades inválidas: registro malformado")
            authority_id = entry.get("authority_id")
            if not _is_identifier(authority_id):
                errors.append(f"{ELECTION_FILE}: authority_id inválido: {authority_id!r}")
                continue
            if authority_id in authorities:
                raise _AuditError(f"{ELECTION_FILE}: autoridade {authority_id!r} repetida")
            h_i = _parse_int(entry.get("public_key"), f"{ELECTION_FILE}: public_key de {authority_id!r}")
            if not 1 < h_i < p - 1 or pow(h_i, q, p) != 1:
                errors.append(f"{ELECTION_FILE}: chave da autoridade {authority_id!r} fora do subgrupo")
            authorities[authority_id] = h_i
            # h = Π h_i, recalculado SÓ com as chaves públicas.
            joint = joint * h_i % p
        published = _parse_int(data.get("joint_public_key"), f"{ELECTION_FILE}: joint_public_key")
        if published != joint:
            errors.append(f"{ELECTION_FILE}: joint_public_key publicada difere de Π h_i")

        candidates = self._parse_candidates(data.get("candidates"))
        voters = self._load_voters(data, errors)

        if errors:
            return None
        return _PublicContext(
            election_id=election_id,
            group=group,
            joint_public_key=joint,
            candidates=candidates,
            voters=MappingProxyType(voters),
            authorities=MappingProxyType(authorities),
        )

    def _parse_group(self, raw: object) -> _Group:
        if type(raw) is not dict:
            raise _AuditError(f"{ELECTION_FILE}: parâmetros do grupo ausentes")
        p = _parse_int(raw.get("p"), "group.p")
        q = _parse_int(raw.get("q"), "group.q")
        g = _parse_int(raw.get("g"), "group.g")
        # Mesmos limites do cadastro, da eleição e da decifração conjunta.
        if (
            p.bit_length() < 2048
            or q.bit_length() < 224
            or not 2 < q < p
            or (p - 1) % q != 0
            or not 1 < g < p - 1
            or pow(g, q, p) != 1
        ):
            raise _AuditError(f"{ELECTION_FILE}: parâmetros de grupo incoerentes ou pequenos demais")
        return _Group(p, q, g)

    @staticmethod
    def _parse_candidates(raw: object) -> tuple[str, ...]:
        if not isinstance(raw, list) or len(raw) < MIN_CANDIDATES:
            raise _AuditError(
                f"{ELECTION_FILE}: a lista de candidatos (pelo menos {MIN_CANDIDATES}) é obrigatória"
            )
        for name in raw:
            # O candidate_id vai na cédula assinada: precisa ser identificador.
            if not _is_identifier(name):
                raise _AuditError(f"{ELECTION_FILE}: candidato inválido: {name!r}")
        if len(set(raw)) != len(raw):
            raise _AuditError(f"{ELECTION_FILE}: candidatos repetidos")
        return tuple(raw)

    def _load_voters(self, election_data: dict, errors: list[str]) -> dict[str, str]:
        from_election = None
        if election_data.get("voters") is not None:
            from_election = _parse_voter_list(election_data["voters"], ELECTION_FILE)

        from_file = None
        if self._path(VOTERS_FILE).exists():
            raw = self._read_json(VOTERS_FILE)
            if type(raw) is dict:
                if raw.get("election_id", election_data["election_id"]) != election_data["election_id"]:
                    errors.append(f"{VOTERS_FILE}: pertence a outra eleição")
                raw = raw.get("voters")
            from_file = _parse_voter_list(raw, VOTERS_FILE)

        if from_election is None and from_file is None:
            raise _AuditError("nenhum cadastro de eleitores publicado")
        # Duas listas divergentes: um eleitor pode ter sido inserido depois
        # do congelamento. Nenhuma das duas é aceita.
        if from_election is not None and from_file is not None and from_election != from_file:
            only_file = sorted(set(from_file) - set(from_election))
            only_election = sorted(set(from_election) - set(from_file))
            changed = sorted(
                v for v in set(from_file) & set(from_election) if from_file[v] != from_election[v]
            )
            errors.append(
                f"{VOTERS_FILE} difere do cadastro em {ELECTION_FILE}: "
                f"só em {VOTERS_FILE} {only_file}, só em {ELECTION_FILE} {only_election}, "
                f"chave diferente {changed}"
            )
        return from_election if from_election is not None else from_file

    # ------------------------------------------------------- quadro público
    def _load_board(self, errors: list[str]) -> list[_BoardEntry]:
        """Registros na ordem do arquivo; ``record=None`` = linha ilegível.

        Cada linha passa pelo leitor estrito do quadro real
        (``hash_chain.read_records``: UTF-8, sem campos repetidos, sem NaN,
        terminada por LF). Uma linha ruim não impede a leitura das demais.
        """
        entries: list[_BoardEntry] = []
        content = self._read_bytes(BOARD_FILE)
        for line_no, line in enumerate(content.splitlines(keepends=True), start=1):
            if not line.strip():
                errors.append(f"linha {line_no}: linha vazia no quadro público")
                continue
            try:
                (record,) = tuple(read_records(io.BytesIO(line)))
            except (BoardError, ValueError):
                errors.append(f"linha {line_no}: registro não é um objeto JSON válido do quadro")
                record = None
            entries.append(_BoardEntry(line_no, record))
        return entries

    # ------------------------------------------------------ a) cadeia de hashes
    def _check_hash_chain(self, errors: list[str], ctx: _PublicContext, entries: list[_BoardEntry]) -> None:
        expected_prev: str | None = genesis_hash(ctx.election_id)
        for position, entry in enumerate(entries):
            where = f"entrada {position}"
            record = entry.record
            if record is None:
                expected_prev = None  # elo perdido: o seguinte não pode ser conferido
                continue
            index = record.get("index")
            if type(index) is not int or index != position:
                errors.append(
                    f"{where}: index {index!r} fora de ordem "
                    "(registro removido, inserido ou reordenado)"
                )
            stored_hash = record.get("hash")
            previous = record.get("previous_hash")
            if not isinstance(stored_hash, str) or not isinstance(previous, str):
                errors.append(f"{where}: campos hash/previous_hash ausentes")
                expected_prev = stored_hash if isinstance(stored_hash, str) else None
                continue
            if expected_prev is not None and previous != expected_prev:
                errors.append(
                    f"{where}: previous_hash não corresponde ao hash da entrada anterior "
                    "(cadeia quebrada: remoção, inserção ou reordenação)"
                )
            body = {k: v for k, v in record.items() if k != "hash"}
            try:
                recomputed = hash_record(body)
            except (BoardError, BallotError) as exc:
                # hash_record valida o formato do registro e da cédula embutida.
                errors.append(f"{where}: registro fora do formato público do quadro ({exc})")
            else:
                if recomputed != stored_hash:
                    errors.append(f"{where}: hash não corresponde ao conteúdo do registro (registro alterado)")
            # O próximo elo aponta para o hash GRAVADO: assim uma alteração é
            # acusada uma única vez, no registro alterado.
            expected_prev = stored_hash

    # ------------------------------------------- b) elegibilidade e unicidade
    @staticmethod
    def _check_eligibility(errors: list[str], ctx: _PublicContext, entries: list[_BoardEntry]) -> None:
        positions: dict[str, list[int]] = {}
        for position, entry in enumerate(entries):
            if entry.record is None:
                continue
            voter_id = _record_voter(entry.record)
            if not _is_identifier(voter_id):
                errors.append(f"entrada {position}: voter_id inválido: {voter_id!r}")
                continue
            if voter_id not in ctx.voters:
                errors.append(f"entrada {position}: eleitor {voter_id!r} não está cadastrado")
            positions.setdefault(voter_id, []).append(position)
        for voter_id, where in positions.items():
            if len(where) > 1:
                errors.append(f"eleitor {voter_id!r} votou {len(where)} vezes (entradas {where})")

    # ---------------------------------------------- c) assinaturas e cifras
    def _entry_ciphertexts(self, ctx: _PublicContext, record: dict) -> tuple[tuple[int, int], ...]:
        """Cifras do registro (forma, candidato e ``[2, p-1]``), via ``board_tally``."""
        try:
            return record_ciphertexts(record, ctx.candidates, ctx.group.p)
        except BoardTallyError as exc:
            raise _AuditError(str(exc)) from None

    def _check_signatures(self, errors: list[str], ctx: _PublicContext, entries: list[_BoardEntry]) -> None:
        p, q = ctx.group.p, ctx.group.q
        seen_c1: dict[int, int] = {}
        for position, entry in enumerate(entries):
            record = entry.record
            if record is None:
                continue
            where = f"entrada {position}"
            try:
                voter_id = _record_voter(record)
                if not _is_identifier(voter_id):
                    raise _AuditError("voter_id inválido: assinatura não verificável")
                key = ctx.voters.get(voter_id)
                if key is None:
                    raise _AuditError(
                        f"eleitor {voter_id!r} sem chave cadastrada: assinatura não verificável"
                    )
                self._verify_record_signature(ctx, record, voter_id, key)
                pairs = self._entry_ciphertexts(ctx, record)
                register_ciphertexts(pairs, position, seen_c1, p=p, q=q)
            except (_AuditError, BoardTallyError) as exc:
                errors.append(f"{where}: {exc}")

    def _verify_record_signature(self, ctx: _PublicContext, record: dict, voter_id: str, key: str) -> None:
        """``verify_signed_ballot`` com a chave CADASTRADA deste eleitor."""
        envelope = {"ballot": record.get("ballot"), "signature": record.get("signature")}
        try:
            verified = self._verify_ballot(
                envelope,
                election_id=ctx.election_id,
                candidate_ids=ctx.candidates,
                voter_public_keys={voter_id: key},
            )
        except InvalidBallotSignatureError:
            raise _AuditError(
                f"assinatura do eleitor {voter_id!r} inválida (cédula adulterada ou forjada)"
            ) from None
        except BallotError as exc:
            raise _AuditError(f"cédula fora do formato ou de outra eleição: {exc}") from None
        except Exception as exc:
            # Verificador que falha = assinatura inválida (lado seguro).
            raise _AuditError(
                f"assinatura do eleitor {voter_id!r} não verificável ({type(exc).__name__})"
            ) from None
        if type(verified) is not dict or verified != record.get("ballot"):
            raise _AuditError(f"assinatura do eleitor {voter_id!r} inválida (verificação inconsistente)")

    # ------------------------------------------- d) agregação homomórfica
    def _check_aggregate(
        self, errors: list[str], ctx: _PublicContext, entries: list[_BoardEntry]
    ) -> dict[str, tuple[int, int]] | None:
        """Recalcula ``Π c1`` e ``Π c2`` e compara; devolve o agregado recalculado."""
        if not entries:
            raise _AuditError("quadro público vazio: produto não pode ser recalculado")
        ballots = []
        for position, entry in enumerate(entries):
            if entry.record is None:
                raise _AuditError(f"entrada {position} ilegível: produto não pode ser recalculado")
            try:
                ballots.append(self._entry_ciphertexts(ctx, entry.record))
            except _AuditError as exc:
                raise _AuditError(f"entrada {position}: {exc}; produto não pode ser recalculado") from None
        group = ctx.group
        products = aggregate_columns(ballots, len(ctx.candidates), p=group.p, q=group.q, g=group.g)
        recomputed = dict(zip(ctx.candidates, products))

        try:
            published = self._read_json_object(AGGREGATE_FILE)
        except _AuditError as exc:
            errors.append(str(exc))
            return recomputed
        if published.get("election_id") != ctx.election_id:
            errors.append(f"{AGGREGATE_FILE}: pertence a outra eleição")
        raw = published.get("ciphertexts")
        if type(raw) is not dict or set(raw) != set(ctx.candidates):
            errors.append(f"{AGGREGATE_FILE}: candidatos diferem dos de {ELECTION_FILE}")
            return recomputed
        for cid in ctx.candidates:
            c1, c2 = recomputed[cid]
            item = raw[cid]
            try:
                if type(item) is not dict or set(item) != {"c1", "c2"}:
                    raise _AuditError("deve ter exatamente c1 e c2")
                pub = (_parse_int(item["c1"], "c1"), _parse_int(item["c2"], "c2"))
            except _AuditError as exc:
                errors.append(f"{AGGREGATE_FILE}: cifra de {cid!r} malformada: {exc}")
                continue
            if pub[0] != c1:
                errors.append(f"{AGGREGATE_FILE}: C1 de {cid!r} difere do produto recalculado do quadro")
            if pub[1] != c2:
                errors.append(f"{AGGREGATE_FILE}: C2 de {cid!r} difere do produto recalculado do quadro")
        return recomputed

    # ------------------------------------------- e) parcelas e resultado
    def _load_partials(self, ctx: _PublicContext, recomputed: dict) -> dict[str, dict[str, int]]:
        """Lê ``authority_partials.json`` REVERIFICANDO cada prova; devolve ``id -> cid -> d``."""
        data = self._read_json_object(PARTIALS_FILE)
        if data.get("election_id") != ctx.election_id:
            raise _AuditError(f"{PARTIALS_FILE}: pertence a outra eleição")
        partials = data.get("partials")
        if not isinstance(partials, list):
            raise _AuditError(f"{PARTIALS_FILE}: sem a lista de parcelas")
        accepted: dict[str, dict[str, int]] = {}
        for raw in partials:
            try:
                authority_id, shares = self._verify_submission(ctx, recomputed, raw)
            except _AuditError as exc:
                raise _AuditError(f"{PARTIALS_FILE}: parcela rejeitada: {exc}") from None
            if authority_id in accepted:
                raise _AuditError(f"{PARTIALS_FILE}: parcela rejeitada: autoridade {authority_id!r} repetida")
            accepted[authority_id] = shares
        return accepted

    def _verify_submission(self, ctx: _PublicContext, recomputed: dict, raw: object) -> tuple[str, dict]:
        if type(raw) is not dict or set(raw) != {"authority_id", "shares"}:
            raise _AuditError("submissão deve ter exatamente authority_id e shares")
        authority_id = raw["authority_id"]
        # A chave usada na verificação vem SEMPRE de election.json.
        h_i = ctx.authorities.get(authority_id) if _is_identifier(authority_id) else None
        if h_i is None:
            raise _AuditError(f"autoridade {authority_id!r} não cadastrada")
        shares = raw["shares"]
        if type(shares) is not dict or set(shares) != set(ctx.candidates):
            raise _AuditError(f"candidatos das parcelas de {authority_id!r} diferem dos da eleição")
        result: dict[str, int] = {}
        for cid in ctx.candidates:
            share = shares[cid]
            if type(share) is not dict or set(share) != {"d", "a1", "a2", "s"}:
                raise _AuditError(f"parcela de {authority_id!r}/{cid!r} deve ter exatamente d, a1, a2 e s")
            values = {name: _parse_int(share[name], f"{name} de {authority_id!r}/{cid!r}")
                      for name in ("d", "a1", "a2", "s")}
            c1 = recomputed[cid][0]
            self._verify_share(ctx, authority_id, h_i, cid, c1, **values)
            result[cid] = values["d"]
        return authority_id, result

    def _verify_share(
        self, ctx: _PublicContext, authority_id: str, h_i: int, cid: str, c1: int,
        *, d: int, a1: int, a2: int, s: int,
    ) -> None:
        """Prova de Chaum-Pedersen de que ``log_g(h_i) = log_C1(d_i)``, só com dados públicos."""
        p, q, g = ctx.group.p, ctx.group.q, ctx.group.g
        for name, value in (("d", d), ("a1", a1), ("a2", a2)):
            if not 2 <= value <= p - 1 or pow(value, q, p) != 1:
                raise _AuditError(f"{name} de {authority_id!r}/{cid!r} fora do subgrupo de ordem q")
        if not 0 <= s < q:
            raise _AuditError(f"s de {authority_id!r}/{cid!r} fora de [0, q)")
        c = self._challenge(ctx, authority_id, cid, h_i, c1, d, a1, a2)
        # g^s = a1 · h_i^c   e   C1^s = a2 · d_i^c
        if pow(g, s, p) != a1 * pow(h_i, c, p) % p:
            raise _AuditError(f"prova de {authority_id!r}/{cid!r} inválida (g^s)")
        if pow(c1, s, p) != a2 * pow(d, c, p) % p:
            raise _AuditError(f"prova de {authority_id!r}/{cid!r} inválida (C1^s)")

    @staticmethod
    def _challenge(ctx: _PublicContext, authority_id: str, cid: str, h_i: int, c1: int,
                   d: int, a1: int, a2: int) -> int:
        """Desafio Fiat-Shamir do protocolo público das parcelas."""
        payload = _canonical_json(
            {
                "domain": PROOF_DOMAIN,
                "election_id": ctx.election_id,
                "authority_id": authority_id,
                "candidate_id": cid,
                "p": str(ctx.group.p),
                "q": str(ctx.group.q),
                "g": str(ctx.group.g),
                "h_i": str(h_i),
                "c1": str(c1),
                "d": str(d),
                "a1": str(a1),
                "a2": str(a2),
            }
        )
        return int.from_bytes(hashlib.sha256(payload).digest(), "big") % ctx.group.q

    def _check_result(
        self, errors: list[str], ctx: _PublicContext, entries: list, recomputed: dict
    ) -> None:
        p, g = ctx.group.p, ctx.group.g

        # Reverifica cada prova contra o agregado RECALCULADO: parcelas de um
        # agregado falso (ou de um quadro truncado) não conferem.
        partials = self._load_partials(ctx, recomputed)
        missing = [a for a in ctx.authorities if a not in partials]
        if missing:
            errors.append(f"{PARTIALS_FILE}: faltam parcelas das autoridades {missing}")

        result = self._read_json_object(RESULT_FILE)
        if result.get("election_id") != ctx.election_id:
            errors.append(f"{RESULT_FILE}: pertence a outra eleição")
        if result.get("authorities", list(ctx.authorities)) != list(ctx.authorities):
            errors.append(f"{RESULT_FILE}: lista de autoridades difere do cadastro")
        totals = result.get("totals")
        if type(totals) is not dict or set(totals) != set(ctx.candidates):
            raise _AuditError(f"{RESULT_FILE}: totais ausentes ou com candidatos diferentes")
        n_ballots = len(entries)
        # Não depende das parcelas: roda mesmo se faltar alguma autoridade.
        self._check_totals_sum(errors, totals, n_ballots)
        if missing:
            return  # sem todas as parcelas, h^R não se cancela: nada a comparar

        for cid in ctx.candidates:
            total = totals[cid]
            if type(total) is not int or not 0 <= total <= n_ballots:
                errors.append(f"{RESULT_FILE}: total de {cid!r} ({total!r}) fora de [0, {n_ballots}]")
                continue
            combined = 1  # D = Π d_i = C1^(Σ x_i) = h^R
            for shares in partials.values():
                combined = combined * shares[cid] % p
            c2 = recomputed[cid][1]
            # C2 = g^T · h^R  <=>  C2 ≡ g^T · D (mod p)
            if c2 != pow(g, total, p) * combined % p:
                errors.append(
                    f"{RESULT_FILE}: total publicado de {cid!r} ({total}) não corresponde "
                    "à decifração conjunta do produto homomórfico"
                )

    @staticmethod
    def _check_totals_sum(errors: list[str], totals: dict, n_ballots: int) -> None:
        """Exige ``Σ totais == nº de cédulas do quadro`` (mesma regra da apuração).

        Igualdade porque não há voto em branco: pela especificação, cada
        cédula cifra 1 para o candidato escolhido e 0 para os demais, e quem se
        abstém não gera registro no quadro. Uma soma diferente prova que ao
        menos uma cédula não cifra exatamente um voto, MESMO que cada total
        decifre corretamente (``C2 ≡ g^T · Π d_i``).

        Detecção AGREGADA: não diz qual cédula nem qual eleitor. Cédulas que
        somam 1 com valores fora de {0, 1} (ex.: ``m = -1`` e ``m = 2``)
        passam; só a prova 0/1 por cifra as detectaria.

        Só é aplicada se todos os totais forem inteiros em ``[0, n_ballots]``:
        os demais já viram erro próprio, um por candidato.
        """
        values = list(totals.values())
        if not all(type(v) is int and 0 <= v <= n_ballots for v in values):
            return
        total = sum(values)
        if total != n_ballots:
            errors.append(
                f"{RESULT_FILE}: soma dos totais ({total}) difere do número de cédulas do "
                f"quadro ({n_ballots}): ao menos uma cédula não cifra exatamente um voto "
                "(detecção agregada, sem identificar o eleitor; sem a prova 0/1, "
                "cédulas como m = -1 e m = 2 continuam indetectáveis)"
            )


# ---------------------------------------------------------------- atalhos e CLI
def audit_election(public_dir: Path | str = DEFAULT_PUBLIC_DIR, **kwargs: Any) -> AuditReport:
    """Atalho: ``Auditor(public_dir, **kwargs).run()``."""
    return Auditor(public_dir, **kwargs).run()


def main(argv: Sequence[str] | None = None) -> int:
    """``python -m src.auditor.auditor [data/public] [--json]``.

    Saída 0 = válida, 1 = inválida, 2 = erro de configuração. ``argv`` permite
    chamar a função de outro código Python (por exemplo, nos testes) sem
    passar pelo ``sys.argv``.
    """
    parser = argparse.ArgumentParser(
        prog="python -m src.auditor.auditor",
        description="Auditor independente da URNA_ONLINE: usa somente os dados públicos.",
    )
    parser.add_argument("public_dir", nargs="?", default=str(DEFAULT_PUBLIC_DIR))
    parser.add_argument("--json", action="store_true", help="relatório em JSON")
    args = parser.parse_args(argv)
    try:
        auditor = Auditor(args.public_dir)
    except (RuntimeError, TypeError, ValueError) as exc:
        print(f"auditor: {exc}", file=sys.stderr)
        return 2
    report = auditor.run()
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(report.format())
    return 0 if report.valid else 1


if __name__ == "__main__":  # processo separado do servidor
    sys.exit(main())
