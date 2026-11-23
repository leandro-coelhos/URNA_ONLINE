"""Ciclo de vida da eleição, elegibilidade e validação das cédulas.

O que este módulo FAZ
---------------------
- Controla a máquina de estados oficial (``src.election.states``), com
  transições estritamente unidirecionais::

      CONFIGURACAO -> CADASTRO -> VOTACAO_ABERTA -> ENCERRADA -> APURACAO -> AUDITADA

  A construção de ``Election`` corresponde a ``CONFIGURACAO`` (grupo e
  candidatos validados), então o objeto já nasce em ``CADASTRO``.
  ``Election.current_state`` é compatível com o ``state_provider`` de
  ``src.server.registration.Registration``.
- Só abre a votação se o cadastro estiver congelado, houver pelo menos
  ``MIN_AUTHORITIES`` (3) autoridades e a chave conjunta ``h`` pertencer ao
  subgrupo de ordem ``q``.
- Aceita cédulas somente em ``VOTACAO_ABERTA``. O ÚNICO formato aceito é o
  envelope público de ``src.crypto.ballots`` (o mesmo que o
  ``src.bulletin_board.board.BulletinBoard`` grava)::

      {"ballot": {"schema_version": 1, "election_id": ..., "voter_id": ...,
                  "ciphertexts": [{"candidate_id": ..., "c1": "<dec>", "c2": "<dec>"}, ...]},
       "signature": "<Base64 de RSA-PSS sobre BALLOT_DOMAIN + JSON canônico>"}

  Verifica estrutura, elegibilidade, voto único, assinatura do eleitor (com
  ``src.crypto.ballots.verify_signed_ballot``), pertencimento de ``(c1, c2)``
  ao subgrupo e reuso de ``c1``.
- Guarda as cédulas aceitas de forma imutável em memória e as persiste, com
  os recibos e a etapa atual, de forma atômica (``tempfile.mkstemp`` +
  ``os.replace``). ``AcceptedBallot.envelope()`` devolve o envelope exato
  que deve ir para o quadro público.

O que este módulo NÃO FAZ
-------------------------
- Não implementa primitivas criptográficas. A assinatura e o formato canônico
  vêm de ``src.crypto.ballots``; a exponenciação modular é o ``pow`` nativo do
  Python (padrão do projeto). A única operação local é o SHA-256 (``hashlib``)
  do recibo.
- Não aceita prova de validade 0/1 (ZKP): o envelope de ``src.crypto.ballots``
  não tem campo para ela, e um campo extra é rejeitado. Limitação documentada
  no README (cenário 7 da T14); ``InvalidProofError`` fica reservado para
  quando ``src.crypto.bit_proof`` fizer parte do formato.
- Não cadastra eleitores nem autoridades: lê o dicionário de
  ``Registration.export_public_data()`` já congelado. A chave conjunta é
  recalculada por ``src.authorities.authority.compute_joint_public_key``.
- Nunca recebe, lê ou guarda chaves privadas (``x_i`` das autoridades ou
  chaves privadas dos eleitores) e nunca vê o voto em claro.
- Não mantém o quadro público encadeado por hashes, não apura e não audita:
  ``start_tally`` e ``mark_audited`` só registram a mudança de etapa.
- Não retoma uma eleição a partir do arquivo persistido: o estado vive no
  objeto. O uso previsto é sequencial, num único processo (como em
  ``demo.py`` e nos testes).
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
import re
import tempfile
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from src.authorities.authority import (
    MIN_AUTHORITIES,
    GroupParams,
    compute_joint_public_key,
)
from src.crypto.ballots import (
    MAX_CIPHERTEXT_DIGITS,
    BallotFormatError,
    InvalidBallotSignatureError,
    canonical_ballot_bytes,
    verify_signed_ballot,
)
from src.election.states import (
    NEXT_STATE,
    ElectionError,
    ElectionState,
    ElectionStateError,
    InvalidStateTransitionError,
    VotingPreconditionError,
)

DEFAULT_BALLOTS_PATH = Path("data/public/accepted_ballots.json")

# Versão do esquema da cédula definida por src.crypto.ballots (v1).
BALLOT_SCHEMA_VERSION = 1
BALLOTS_SCHEMA_VERSION = 2  # accepted_ballots.json: v2 = envelopes de src.crypto.ballots

# Separador de domínio do recibo: o mesmo hash não serve para outro documento.
RECEIPT_DOMAIN = b"URNA_ONLINE:ELECTION-RECEIPT:v1\x00"

# Mesma regra de identificador do cadastro, das autoridades e de
# src.crypto.ballots. Só letras, números, '_' e '-': bloqueia espaços
# invisíveis e path traversal ("../x").
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
_DECIMAL_PATTERN = re.compile(r"[1-9][0-9]*")

# README: a demonstração tem dois candidatos; uma eleição precisa de opções.
MIN_CANDIDATES = 2

# Limites para entrada não autenticada. RSA de 8192 bits (máximo do cadastro)
# gera assinaturas de 1024 bytes; nada maior é legítimo.
MAX_SIGNATURE_BYTES = 1024
_MAX_SIGNATURE_B64 = 4 * ((MAX_SIGNATURE_BYTES + 2) // 3)

_ENVELOPE_FIELDS = frozenset({"ballot", "signature"})
_BALLOT_FIELDS = frozenset({"schema_version", "election_id", "voter_id", "ciphertexts"})
_CIPHERTEXT_FIELDS = frozenset({"candidate_id", "c1", "c2"})


# ------------------------------------------------------------------------ erros
# ElectionError, ElectionStateError, InvalidStateTransitionError e
# VotingPreconditionError vêm de src.election.states e continuam importáveis
# daqui, por compatibilidade.
class VotingClosedError(ElectionStateError):
    """Cédula enviada fora de ``VOTACAO_ABERTA``."""


class VoteRejectedError(ElectionError):
    """Base das rejeições de cédula. Cédula rejeitada nunca é registrada."""


class IneligibleVoterError(VoteRejectedError):
    """``voter_id`` não consta no cadastro congelado."""


class DuplicateVoteError(VoteRejectedError):
    """O eleitor já tem voto registrado; o voto original é preservado."""


class InvalidBallotError(VoteRejectedError):
    """Cédula malformada, com cifras fora do subgrupo ou assinatura inválida."""


class InvalidSignatureError(InvalidBallotError):
    """Assinatura ausente, malformada, adulterada ou feita com outra chave."""


class InvalidProofError(InvalidBallotError):
    """Reservado: prova de validade 0/1 inválida.

    O formato atual (``src.crypto.ballots``) não transporta provas; este erro
    só passará a ser lançado quando ``src.crypto.bit_proof`` integrar a cédula.
    """


# ------------------------------------------------------------ registros públicos
@dataclass(frozen=True)
class Receipt:
    """Recibo entregue ao eleitor: posição e hash da cédula aceita. Não revela o voto."""

    index: int
    voter_id: str
    receipt: str


@dataclass(frozen=True)
class AcceptedBallot:
    """Cédula aceita, imutável, só com dados públicos.

    ``ballot_json`` é o JSON canônico (``src.crypto.ballots``) da cédula
    assinada, guardado como ``str`` imutável; ``ciphertexts`` tem um par
    ``(c1, c2)`` inteiro por candidato, na ordem de ``Election.candidates``.
    """

    index: int
    voter_id: str
    ciphertexts: tuple[tuple[int, int], ...]
    ballot_json: str
    signature: str
    receipt: str

    @property
    def ballot(self) -> dict:
        """Cópia nova da cédula assinada (formato de ``src.crypto.ballots``)."""
        return json.loads(self.ballot_json)

    def envelope(self) -> dict:
        """Cópia nova do envelope exato aceito: ``{"ballot": ..., "signature": ...}``.

        É o que ``BulletinBoard.append`` recebe; qualquer alteração invalida a
        assinatura, e o quadro reverifica tudo.
        """
        return {"ballot": self.ballot, "signature": self.signature}

    def to_dict(self) -> dict:
        """Cópia nova e JSON-compatível, gravada em ``accepted_ballots.json``."""
        return {
            "index": self.index,
            "voter_id": self.voter_id,
            "ballot": self.ballot,
            "signature": self.signature,
            "receipt": self.receipt,
        }


@dataclass(frozen=True)
class _ParsedBallot:
    voter_id: str
    ciphertexts: tuple[tuple[int, int], ...]
    ballot: dict
    ballot_json: str
    signature: str


# -------------------------------------------------------------------- validação
def validate_identifier(identifier: object, what: str = "identificador") -> str:
    """Valida um identificador com a regra do cadastro e o devolve.

    Lança ``InvalidBallotError``. Não normaliza espaços nem maiúsculas: o id
    precisa ter exatamente a grafia cadastrada. ``fullmatch`` impede que
    "eleitor-1\\n" ou "eleitor-1/../x" passem por terem um prefixo válido.
    """
    if not isinstance(identifier, str) or not IDENTIFIER_PATTERN.fullmatch(identifier):
        raise InvalidBallotError(
            f"{what} inválido: use de 1 a 64 caracteres ASCII (letras, números, "
            "'_' ou '-'), começando por letra ou número."
        )
    return identifier


def _is_strict_int(value: object) -> bool:
    # type(...) is int, e não isinstance: bool é subclasse de int.
    return type(value) is int


def compute_receipt(ballot: dict, signature: str) -> str:
    """Recibo = SHA-256(RECEIPT_DOMAIN || JSON canônico da cédula || 0x0A || assinatura).

    O JSON canônico é o de ``src.crypto.ballots.canonical_ballot_bytes``
    (compacto, sem quebra de linha literal), então o separador não é ambíguo.
    Qualquer pessoa recalcula o recibo a partir do registro do quadro público
    (``record["ballot"]`` e ``record["signature"]``) e o eleitor, a partir do
    envelope que enviou. Incluir a assinatura identifica a cédula exatamente
    como foi aceita. Lança ``InvalidBallotError`` se a cédula estiver fora do
    formato.
    """
    try:
        canonical = canonical_ballot_bytes(ballot)
    except BallotFormatError as exc:
        raise InvalidBallotError(f"cédula fora do formato público: {exc}") from None
    if not isinstance(signature, str) or not signature.isascii():
        raise InvalidSignatureError("signature deve ser texto base64 ASCII")
    return hashlib.sha256(RECEIPT_DOMAIN + canonical + b"\n" + signature.encode("ascii")).hexdigest()


def _decode_signature(signature: object) -> bytes:
    """Base64 estrito e canônico."""
    if not isinstance(signature, str) or not signature or not signature.isascii():
        raise InvalidSignatureError("signature deve ser texto base64 não vazio")
    if len(signature) > _MAX_SIGNATURE_B64:
        raise InvalidSignatureError("signature grande demais")
    try:
        raw = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidSignatureError("signature não é base64 válido") from exc
    # Base64 é maleável ("QQ==" e "QR==" decodificam igual). Exigir a forma
    # canônica garante uma única representação e, portanto, um único recibo.
    if not raw or base64.b64encode(raw).decode("ascii") != signature:
        raise InvalidSignatureError("signature não está em base64 canônico")
    return raw


def _require_fields(obj: dict, required: frozenset, what: str) -> None:
    keys = set(obj)
    missing = required - keys
    if missing:
        raise InvalidBallotError(f"{what}: campos obrigatórios ausentes: {sorted(missing)}")
    extra = keys - required
    if extra:
        # Campos extras não estariam no formato assinado e seriam
        # contrabandeados para o arquivo público (inclusive "proof").
        raise InvalidBallotError(f"{what}: campos desconhecidos: {sorted(map(repr, extra))}")


def _validate_group(group: GroupParams) -> None:
    """Coerência do grupo. Primalidade é responsabilidade do módulo de crypto.

    Limites de tamanho iguais aos de ``Registration.__init__``.
    """
    if not isinstance(group, GroupParams):
        raise TypeError("group deve expor os atributos inteiros p, q e g")
    p, q, g = group.p, group.q, group.g
    if not all(_is_strict_int(v) for v in (p, q, g)):
        raise ValueError("p, q e g devem ser int")
    if (
        p.bit_length() < 2048
        or q.bit_length() < 224
        or not 2 < q < p
        or (p - 1) % q != 0
        or not 1 < g < p - 1
    ):
        raise ValueError("parâmetros de grupo incoerentes ou pequenos demais")
    # g fora do subgrupo de ordem q faria as cifras vazarem informação sobre m.
    if pow(g, q, p) != 1:
        raise ValueError("g não pertence ao subgrupo de ordem q")


def _validate_candidates(candidates: object) -> tuple[str, ...]:
    if isinstance(candidates, (str, bytes)) or not isinstance(candidates, Sequence):
        raise ValueError("candidates deve ser uma lista de identificadores")
    names = tuple(candidates)
    if len(names) < MIN_CANDIDATES:
        raise ValueError(f"a eleição exige pelo menos {MIN_CANDIDATES} candidatos")
    for name in names:
        # O candidate_id vai dentro da cédula assinada (src.crypto.ballots),
        # que só aceita identificadores: "Maria Silva" vira "Maria_Silva".
        if not isinstance(name, str) or not IDENTIFIER_PATTERN.fullmatch(name):
            raise ValueError(
                f"candidato inválido: {name!r} (use um identificador: letras, números, '_' ou '-')"
            )
    if len(set(names)) != len(names):
        raise ValueError("candidatos repetidos")
    return names


# ---------------------------------------------------------------------- eleição
class Election:
    """Uma eleição: etapa atual, eleitores habilitados e cédulas aceitas.

    Fluxo típico::

        election = Election("eleicao-2026", group, ["Alice", "Bob"])
        registration = Registration("eleicao-2026", p=group.p, q=group.q,
                                    state_provider=election.current_state)
        ...  # cadastro de eleitores e autoridades
        registration.freeze()
        public_data = registration.export_public_data()
        publish_joint_public_key(public_data, group, "data/public/election.json")
        election.open_voting(public_data, election_path="data/public/election.json")
        receipt = election.submit_ballot(envelope)   # envelope de src.crypto.ballots
        election.close_voting()
        election.start_tally()   # antes das parcelas das autoridades
        election.mark_audited()  # após o auditor independente

    Contrato:
    - A construção é a etapa ``CONFIGURACAO`` (grupo e candidatos validados
      aqui); por isso o objeto já nasce em ``CADASTRO``.
    - Transições avançam uma etapa por vez, conforme ``NEXT_STATE``; nunca
      voltam. Cada mudança é persistida antes de ser aplicada em memória.
    - O cadastro é copiado uma única vez, ao abrir a votação.
    - A assinatura é SEMPRE verificada com ``src.crypto.ballots`` e a chave
      do cadastro congelado; não há como desativá-la.
    - Nenhum método recebe ou devolve chave privada.
    """

    def __init__(
        self,
        election_id: str,
        group: GroupParams,
        candidates: Sequence[str],
        *,
        ballots_path: Path | str = DEFAULT_BALLOTS_PATH,
    ) -> None:
        try:
            validate_identifier(election_id, "election_id")
        except InvalidBallotError as exc:
            raise ValueError(str(exc)) from None

        _validate_group(group)

        self._election_id = election_id
        self._group = group
        self._candidates = _validate_candidates(candidates)
        self._ballots_path = Path(ballots_path)

        # CONFIGURACAO terminou com sucesso (validações acima): a eleição
        # começa na etapa seguinte, a única em que Registration aceita inclusões.
        self._state = NEXT_STATE[ElectionState.CONFIGURACAO]
        # A verificação "ainda não votou" e o registro do voto acontecem sob a
        # mesma trava: dois envios simultâneos do mesmo eleitor não passam
        # ambos pela checagem de duplicidade.
        self._lock = threading.RLock()

        # Preenchidos em open_voting a partir do cadastro congelado.
        self._voters: MappingProxyType[str, str] = MappingProxyType({})
        self._joint_public_key: int | None = None

        # Estruturas imutáveis: cada voto aceito gera uma tupla/frozenset novos.
        self._ballots: tuple[AcceptedBallot, ...] = ()
        self._voted: frozenset[str] = frozenset()
        self._used_c1: frozenset[int] = frozenset()

    # -------------------------------------------------------------- consultas
    def current_state(self) -> str:
        """Etapa atual como string, para ``Registration(state_provider=...)``."""
        return self._state.value

    @property
    def state(self) -> ElectionState:
        return self._state

    @property
    def election_id(self) -> str:
        return self._election_id

    @property
    def group(self) -> GroupParams:
        return self._group

    @property
    def candidates(self) -> tuple[str, ...]:
        return self._candidates

    @property
    def joint_public_key(self) -> int | None:
        """``h`` validado na abertura; ``None`` enquanto em ``CADASTRO``."""
        return self._joint_public_key

    @property
    def eligible_voters(self) -> tuple[str, ...]:
        return tuple(self._voters)

    @property
    def accepted_ballots(self) -> tuple[AcceptedBallot, ...]:
        """Cédulas aceitas, na ordem de chegada."""
        return self._ballots

    def has_voted(self, voter_id: str) -> bool:
        return voter_id in self._voted

    # ------------------------------------------------------------- transições
    def _require_next(self, target: ElectionState) -> None:
        # Só a sucessora imediata é aceita: cobre retrocesso, salto
        # (CADASTRO -> ENCERRADA) e repetição (abrir duas vezes).
        if NEXT_STATE.get(self._state) is not target:
            raise InvalidStateTransitionError(
                f"transição {self._state.value} -> {target.value} não permitida"
            )

    def _advance(self, target: ElectionState) -> None:
        """Transição sem pré-condições extras: valida, persiste e só então aplica."""
        with self._lock:
            self._require_next(target)
            # Se a escrita falhar, a etapa em memória continua a anterior.
            self._persist(target, self._ballots, self._joint_public_key)
            self._state = target

    def open_voting(
        self,
        public_data: dict,
        *,
        election_path: Path | str | None = None,
    ) -> None:
        """``CADASTRO -> VOTACAO_ABERTA``, se todas as pré-condições valerem.

        ``public_data`` é o retorno de ``Registration.export_public_data()``.
        Se ``election_path`` for informado, o ``election.json`` publicado
        também precisa trazer o mesmo grupo e a mesma ``joint_public_key``.

        Lança ``InvalidStateTransitionError`` fora de ``CADASTRO`` e
        ``VotingPreconditionError`` se o cadastro não estiver congelado, for de
        outra eleição, tiver menos de 3 autoridades ou nenhum eleitor; se ``h``
        estiver fora do subgrupo; se a publicação divergir; ou se já existir um
        arquivo de cédulas. Em qualquer falha, a eleição continua em ``CADASTRO``.
        """
        with self._lock:
            self._require_next(ElectionState.VOTACAO_ABERTA)
            if type(public_data) is not dict:
                raise VotingPreconditionError("public_data deve ser o dict de export_public_data()")
            # Cópia profunda: alterações posteriores no dict do chamador não
            # mudam o snapshot da eleição.
            snapshot = copy.deepcopy(public_data)

            # 1) Cadastro congelado: senão, eleitores ou autoridades poderiam
            #    entrar depois de h ter sido calculado.
            if snapshot.get("frozen") is not True:
                raise VotingPreconditionError("o cadastro precisa estar congelado (freeze())")
            if snapshot.get("election_id") != self._election_id:
                raise VotingPreconditionError("o cadastro pertence a outra eleição")

            # 2) Pelo menos três autoridades (critério de aceitação).
            authorities = snapshot.get("authorities")
            if not isinstance(authorities, list) or len(authorities) < MIN_AUTHORITIES:
                raise VotingPreconditionError(
                    f"a votação exige pelo menos {MIN_AUTHORITIES} autoridades cadastradas"
                )

            # 3) h recalculado só a partir das chaves públicas (nunca de Σ x_i)
            #    e validado no subgrupo.
            try:
                joint_key = compute_joint_public_key(
                    snapshot, self._group, min_authorities=MIN_AUTHORITIES
                )
            except (ValueError, TypeError) as exc:  # JointKeyError herda de ValueError
                raise VotingPreconditionError(f"chave conjunta inválida: {exc}") from exc
            self._check_joint_key(joint_key)

            if election_path is not None:
                self._check_published(Path(election_path), joint_key)

            voters = self._parse_voters(snapshot.get("voters"))

            # Não sobrescrevemos cédulas de outra execução: seriam perdidas
            # sem aviso.
            if self._ballots_path.exists():
                raise VotingPreconditionError(
                    f"{self._ballots_path} já existe; mova-o antes de abrir nova votação"
                )

            # Persiste primeiro; só então muda a memória. Se a escrita falhar,
            # nada muda e a eleição segue em CADASTRO.
            self._persist(ElectionState.VOTACAO_ABERTA, (), joint_key)
            self._voters = voters
            self._joint_public_key = joint_key
            self._state = ElectionState.VOTACAO_ABERTA

    def _check_joint_key(self, h: int) -> None:
        p, q = self._group.p, self._group.q
        # h = 1 cifraria trivialmente (c2 = g^m); h fora do subgrupo vazaria
        # informação sobre m. Com q primo, h^q ≡ 1 e h ≠ 1 garantem ordem q.
        if not _is_strict_int(h) or not 2 <= h <= p - 1 or pow(h, q, p) != 1:
            raise VotingPreconditionError("chave conjunta fora do subgrupo de ordem q")

    def _check_published(self, path: Path, joint_key: int) -> None:
        try:
            with open(path, encoding="utf-8") as fh:
                published = json.load(fh)
        except FileNotFoundError:
            raise VotingPreconditionError(f"{path} não existe: publique a chave conjunta") from None
        except (OSError, ValueError) as exc:
            raise VotingPreconditionError(f"{path} ilegível: {exc}") from exc
        if type(published) is not dict:
            raise VotingPreconditionError(f"{path} não contém um objeto JSON")
        expected_group = {
            "p": str(self._group.p),
            "q": str(self._group.q),
            "g": str(self._group.g),
        }
        if published.get("group") != expected_group:
            raise VotingPreconditionError("grupo publicado difere do grupo da eleição")
        if published.get("joint_public_key") != str(joint_key):
            raise VotingPreconditionError("joint_public_key publicada difere da recalculada")
        if published.get("frozen") is not True:
            raise VotingPreconditionError("a chave foi publicada antes do congelamento")

    @staticmethod
    def _parse_voters(raw: object) -> MappingProxyType[str, str]:
        if not isinstance(raw, list) or not raw:
            raise VotingPreconditionError("nenhum eleitor cadastrado")
        voters: dict[str, str] = {}
        for entry in raw:
            if type(entry) is not dict:
                raise VotingPreconditionError("registro de eleitor malformado")
            try:
                voter_id = validate_identifier(entry.get("voter_id"), "voter_id")
            except InvalidBallotError as exc:
                raise VotingPreconditionError(str(exc)) from None
            # Aceita "public_key" (interface combinada) e "public_key_pem"
            # (nome usado pelo registration.py atual).
            key = entry.get("public_key", entry.get("public_key_pem"))
            if not isinstance(key, str) or not key.strip():
                raise VotingPreconditionError(f"chave pública do eleitor {voter_id!r} ausente")
            # Defesa extra: este módulo nunca deve segurar chave privada,
            # nem se alguém a cadastrar por engano.
            if "PRIVATE KEY" in key:
                raise VotingPreconditionError(f"o eleitor {voter_id!r} tem chave privada no cadastro")
            if voter_id in voters:
                raise VotingPreconditionError(f"eleitor {voter_id!r} repetido no cadastro")
            voters[voter_id] = key
        # Visão somente leitura; o dict original não escapa do método.
        return MappingProxyType(voters)

    def close_voting(self) -> None:
        """``VOTACAO_ABERTA -> ENCERRADA``. Depois disso nenhuma cédula entra."""
        self._advance(ElectionState.ENCERRADA)

    def start_tally(self) -> None:
        """``ENCERRADA -> APURACAO``. As parcelas são tratadas por ``src.authorities``."""
        self._advance(ElectionState.APURACAO)

    def mark_audited(self) -> None:
        """``APURACAO -> AUDITADA``, após o auditor independente. Etapa terminal."""
        self._advance(ElectionState.AUDITADA)

    # ---------------------------------------------------------------- votação
    def submit_ballot(self, envelope: dict) -> Receipt:
        """Valida e registra um envelope de ``src.crypto.ballots``; devolve o recibo.

        Ordem das verificações (qualquer falha rejeita sem registrar nada):

        1. etapa ``VOTACAO_ABERTA`` (``VotingClosedError``);
        2. estrutura do envelope e da cédula, eleição, candidatos na ordem da
           eleição, cifras como strings decimais em ``[2, p-1]`` e sem ``c1``
           repetido, e o formato canônico de ``src.crypto.ballots``
           (``InvalidBallotError``);
        3. eleitor no cadastro congelado (``IneligibleVoterError``);
        4. eleitor ainda sem voto (``DuplicateVoteError``);
        5. assinatura com a chave cadastrada, por
           ``src.crypto.ballots.verify_signed_ballot`` (``InvalidSignatureError``);
        6. ``c1^q ≡ c2^q ≡ 1 (mod p)`` e ``c1`` sem reuso (``InvalidBallotError``).

        Checagens baratas vêm primeiro; a exponenciação modular (6) só roda
        para cédulas já autenticadas (5).
        """
        with self._lock:
            if self._state is not ElectionState.VOTACAO_ABERTA:
                raise VotingClosedError(
                    "cédulas só são aceitas em VOTACAO_ABERTA; "
                    f"etapa atual: {self._state.value}"
                )

            parsed = self._parse_envelope(envelope)

            voter_key = self._voters.get(parsed.voter_id)
            if voter_key is None:
                raise IneligibleVoterError(f"eleitor {parsed.voter_id!r} não está habilitado")
            if parsed.voter_id in self._voted:
                # Nada abaixo é executado: o voto original fica intacto.
                raise DuplicateVoteError(f"eleitor {parsed.voter_id!r} já votou")

            self._check_signature(parsed, voter_key)
            self._check_subgroup(parsed.ciphertexts)

            record = AcceptedBallot(
                index=len(self._ballots),
                voter_id=parsed.voter_id,
                ciphertexts=parsed.ciphertexts,
                ballot_json=parsed.ballot_json,
                signature=parsed.signature,
                receipt=compute_receipt(parsed.ballot, parsed.signature),
            )
            new_ballots = self._ballots + (record,)
            # Persiste antes de atualizar a memória: se a escrita falhar, o
            # voto não conta e o eleitor pode reenviar.
            self._persist(self._state, new_ballots, self._joint_public_key)
            self._ballots = new_ballots
            self._voted = self._voted | {parsed.voter_id}
            self._used_c1 = self._used_c1 | {c1 for c1, _ in parsed.ciphertexts}
            return Receipt(record.index, record.voter_id, record.receipt)

    def _parse_envelope(self, envelope: object) -> _ParsedBallot:
        """Validação estrutural; não depende de quem é o eleitor."""
        if type(envelope) is not dict:
            raise InvalidBallotError("o envelope da cédula deve ser um dict")
        _require_fields(envelope, _ENVELOPE_FIELDS, "envelope")
        ballot = envelope["ballot"]
        if type(ballot) is not dict:
            raise InvalidBallotError("ballot deve ser um objeto JSON (dict)")
        _require_fields(ballot, _BALLOT_FIELDS, "ballot")

        version = ballot["schema_version"]
        if not _is_strict_int(version) or version != BALLOT_SCHEMA_VERSION:
            raise InvalidBallotError(f"versão de cédula não suportada: {version!r}")
        validate_identifier(ballot["election_id"], "election_id")
        if ballot["election_id"] != self._election_id:
            raise InvalidBallotError("a cédula pertence a outra eleição")
        voter_id = validate_identifier(ballot["voter_id"], "voter_id")
        ciphertexts = self._parse_ciphertexts(ballot["ciphertexts"])

        # Autoridade final do formato: os mesmos bytes que o eleitor assinou,
        # o quadro público grava e o auditor reverifica.
        try:
            canonical = canonical_ballot_bytes(ballot)
        except BallotFormatError as exc:
            raise InvalidBallotError(f"cédula fora do formato público: {exc}") from None

        signature = envelope["signature"]
        _decode_signature(signature)
        ballot_json = canonical.decode("ascii")
        return _ParsedBallot(voter_id, ciphertexts, json.loads(ballot_json), ballot_json, signature)

    def _parse_ciphertexts(self, raw: object) -> tuple[tuple[int, int], ...]:
        if type(raw) is not list:
            raise InvalidBallotError("ciphertexts deve ser uma lista")
        # Uma cifra por candidato: menos esconderia candidatos; mais permitiria
        # votar em opção inexistente.
        if len(raw) != len(self._candidates):
            raise InvalidBallotError(
                f"esperadas {len(self._candidates)} cifras (uma por candidato), "
                f"recebidas {len(raw)}"
            )
        p = self._group.p
        pairs: list[tuple[int, int]] = []
        for position, item in enumerate(raw):
            if type(item) is not dict or set(item) != _CIPHERTEXT_FIELDS:
                raise InvalidBallotError(
                    f"cifra {position} deve ter exatamente candidate_id, c1 e c2"
                )
            expected = self._candidates[position]
            if item["candidate_id"] != expected:
                raise InvalidBallotError(
                    f"cifra {position}: candidate_id {item['candidate_id']!r} difere de "
                    f"{expected!r} (candidatos ou ordem não correspondem à eleição)"
                )
            values = []
            for name in ("c1", "c2"):
                value = item[name]
                # Strings decimais sem sinal nem zeros à esquerda, como em
                # src.crypto.ballots: int, bool ou float seriam outra
                # representação dos mesmos bytes assinados.
                if (
                    type(value) is not str
                    or not 1 <= len(value) <= MAX_CIPHERTEXT_DIGITS
                    or not _DECIMAL_PATTERN.fullmatch(value)
                ):
                    raise InvalidBallotError(
                        f"{name} da cifra {position} deve ser string decimal positiva "
                        "(sem sinal, espaços ou zeros à esquerda)"
                    )
                number = int(value)
                # c1 = 1 significaria r = 0, e então c2 = g^m revelaria o voto.
                # Valores >= p não estão reduzidos e dariam várias
                # representações da mesma cifra.
                if not 2 <= number <= p - 1:
                    raise InvalidBallotError(f"{name} da cifra {position} fora de [2, p-1]")
                values.append(number)
            pairs.append((values[0], values[1]))
        c1_values = [c1 for c1, _ in pairs]
        # Mesmo c1 em duas cifras = mesmo r: c2/c2' = g^(m-m') revelaria se os
        # votos são iguais.
        if len(set(c1_values)) != len(c1_values):
            raise InvalidBallotError("c1 repetido dentro da cédula (aleatoriedade reutilizada)")
        return tuple(pairs)

    def _check_signature(self, parsed: _ParsedBallot, voter_key: str) -> None:
        # A chave vem SEMPRE do cadastro congelado, nunca da cédula: uma cédula
        # assinada por terceiros não passa, mesmo que traga uma chave própria.
        # Só a chave deste eleitor é passada ao verificador.
        envelope = {"ballot": copy.deepcopy(parsed.ballot), "signature": parsed.signature}
        try:
            verified = verify_signed_ballot(
                envelope,
                election_id=self._election_id,
                candidate_ids=self._candidates,
                voter_public_keys={parsed.voter_id: voter_key},
            )
        except InvalidBallotSignatureError as exc:
            raise InvalidSignatureError(f"assinatura inválida: {exc}") from exc
        except Exception as exc:
            # Qualquer outra falha do verificador é tratada como assinatura
            # inválida: rejeitar é o lado seguro.
            raise InvalidSignatureError("assinatura inválida") from exc
        # O verificador devolve a cédula autenticada: ela precisa ser
        # exatamente a que será registrada (nada de "ok", True ou outra cédula).
        if type(verified) is not dict or verified != parsed.ballot:
            raise InvalidSignatureError("assinatura inválida")

    def _check_subgroup(self, ciphertexts: tuple[tuple[int, int], ...]) -> None:
        p, q = self._group.p, self._group.q
        for position, (c1, c2) in enumerate(ciphertexts):
            # Elementos fora do subgrupo (ex.: p-1 ou não-resíduo quadrático)
            # podem vazar um bit do voto e quebrar a soma homomórfica.
            if pow(c1, q, p) != 1 or pow(c2, q, p) != 1:
                raise InvalidBallotError(f"cifra {position} fora do subgrupo de ordem q")
            # Copiar a cifra de outro eleitor replicaria o voto dele sem
            # conhecê-lo; reusar r vaza a relação entre os votos.
            if c1 in self._used_c1:
                raise InvalidBallotError(f"c1 da cifra {position} já usado em outra cédula")

    # ----------------------------------------------------------- persistência
    def _persist(
        self,
        state: ElectionState,
        ballots: tuple[AcceptedBallot, ...],
        joint_key: int | None,
    ) -> None:
        """Grava etapa, cédulas e recibos. Só dados públicos."""
        data = {
            "schema_version": BALLOTS_SCHEMA_VERSION,
            "election_id": self._election_id,
            "state": state.value,
            "candidates": list(self._candidates),
            "joint_public_key": None if joint_key is None else str(joint_key),
            "ballots": [b.to_dict() for b in ballots],
        }
        _atomic_write_json(self._ballots_path, data)


def _atomic_write_json(path: Path, data: dict) -> None:
    """Escrita atômica: ``mkstemp`` na mesma pasta + ``os.replace``.

    Na mesma partição a renomeação é atômica: quem lê vê a versão anterior
    inteira ou a nova inteira, nunca um JSON pela metade. ``sort_keys`` torna
    a saída determinística para diff e hash do auditor.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        # BaseException inclui KeyboardInterrupt: nunca deixamos .tmp órfão.
        Path(tmp).unlink(missing_ok=True)
        raise
