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
- Aceita cédulas somente em ``VOTACAO_ABERTA``, verificando estrutura,
  elegibilidade, voto único, assinatura do eleitor, pertencimento de
  ``(c1, c2)`` ao subgrupo e, quando houver, a prova de validade (ZKP).
- Guarda as cédulas aceitas de forma imutável em memória e as persiste, com
  os recibos e a etapa atual, de forma atômica (``tempfile.mkstemp`` +
  ``os.replace``).

O que este módulo NÃO FAZ
-------------------------
- Não implementa primitivas criptográficas. A exponenciação modular vem de
  ``src.crypto.group.mod_exp`` (ou é injetada). A verificação de assinatura e
  a de prova são funções injetadas, fornecidas pelo módulo de crypto. A única
  operação local é o SHA-256 (``hashlib``) que identifica o recibo.
- Não cadastra eleitores nem autoridades: lê o dicionário de
  ``Registration.export_public_data()`` já congelado. A chave conjunta é
  recalculada por ``src.authorities.authority.compute_joint_public_key``.
- Nunca recebe, lê ou guarda chaves privadas (``x_i`` das autoridades ou
  chaves privadas dos eleitores) e nunca vê o voto em claro.
- Não mantém o quadro público encadeado por hashes, não apura e não audita:
  ``start_tally`` e ``mark_audited`` só registram a mudança de etapa. Esses
  módulos consomem ``Election.accepted_ballots`` ou o arquivo salvo.
- Não retoma uma eleição a partir do arquivo persistido: o estado vive no
  objeto. O uso previsto é sequencial, pela CLI.
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
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from src.authorities.authority import (
    MIN_AUTHORITIES,
    GroupParams,
    compute_joint_public_key,
)
from src.election.states import (
    NEXT_STATE,
    ElectionError,
    ElectionState,
    ElectionStateError,
    InvalidStateTransitionError,
    VotingPreconditionError,
)

# Importação defensiva: se src/crypto ainda não estiver nesta branch, o módulo
# continua importável e o mod_exp pode ser injetado no construtor. NÃO há
# implementação local de reserva: isso seria reimplementar a primitiva.
try:
    from src.crypto.group import mod_exp as _default_mod_exp
except ImportError:  # pragma: no cover - depende da branch
    _default_mod_exp = None

DEFAULT_BALLOTS_PATH = Path("data/public/accepted_ballots.json")

# Separador de domínio da mensagem assinada: uma assinatura feita pelo eleitor
# para outro fim (ou outra versão do formato) não vale como cédula.
BALLOT_TYPE = "URNA_ONLINE/ballot"
BALLOT_VERSION = 1
BALLOTS_SCHEMA_VERSION = 1

# Mesma regra de identificador do cadastro e das autoridades. Só letras,
# números, '_' e '-': bloqueia espaços invisíveis e path traversal ("../x").
# Não usamos o retorno de validate_authority_id, cuja mensagem fala de
# autoridade; a regra é a mesma, e um teste deve compará-las.
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")

# A demonstração tem dois candidatos; uma eleição precisa de opções.
MIN_CANDIDATES = 2
MAX_CANDIDATE_NAME = 128

# Limites para entrada não autenticada. RSA de 8192 bits (máximo do cadastro)
# gera assinaturas de 1024 bytes; nada maior é legítimo.
MAX_SIGNATURE_BYTES = 1024
_MAX_SIGNATURE_B64 = 4 * ((MAX_SIGNATURE_BYTES + 2) // 3)
MAX_PROOF_BYTES = 64 * 1024

_REQUIRED_FIELDS = frozenset({"election_id", "voter_id", "ciphertexts", "signature"})
_OPTIONAL_FIELDS = frozenset({"proof"})

# Contratos das funções injetadas:
#   mod_exp(base, exp, mod) -> int
#   signature_verifier(voter_public_key: str, message: bytes, signature: bytes) -> bool
#   proof_verifier(proof: dict, ciphertexts: tuple[tuple[int, int], ...],
#                  group: GroupParams, joint_public_key: int) -> bool
# Se a interface real do módulo de crypto for outra, injete um adaptador.
ModExp = Callable[[int, int, int], int]
SignatureVerifier = Callable[[str, bytes, bytes], bool]
ProofVerifier = Callable[[dict, tuple, GroupParams, int], bool]


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
    """Cédula malformada, com cifras fora do subgrupo, assinatura ou prova inválidas."""


class InvalidSignatureError(InvalidBallotError):
    """Assinatura ausente, malformada, adulterada ou feita com outra chave."""


class InvalidProofError(InvalidBallotError):
    """Prova de validade ausente (quando exigida), sem verificador ou inválida."""


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

    ``ciphertexts`` tem um par ``(c1, c2)`` por candidato, na ordem de
    ``Election.candidates``. A prova fica como JSON canônico (``str``,
    imutável) em vez de ``dict`` (mutável).
    """

    index: int
    voter_id: str
    ciphertexts: tuple[tuple[int, int], ...]
    proof_json: str | None
    signature: str
    receipt: str

    def to_dict(self) -> dict:
        """Cópia nova e JSON-compatível; inteiros grandes viram strings decimais."""
        return {
            "index": self.index,
            "voter_id": self.voter_id,
            "ciphertexts": _ciphertexts_to_json(self.ciphertexts),
            "proof": None if self.proof_json is None else json.loads(self.proof_json),
            "signature": self.signature,
            "receipt": self.receipt,
        }


@dataclass(frozen=True)
class _ParsedBallot:
    voter_id: str
    ciphertexts: tuple[tuple[int, int], ...]
    signature: str
    signature_raw: bytes
    proof: dict | None
    proof_json: str | None


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
    # type(...) is int, e não isinstance: bool é subclasse de int, então
    # True passaria como o número 1 numa cifra.
    return type(value) is int


def _canonical_json(obj: Any) -> bytes:
    """Mesmos dados, mesmos bytes: chaves ordenadas, sem espaços, ASCII, sem NaN.

    Eleitor, servidor e auditor precisam gerar bytes idênticos para que a
    assinatura e o recibo confiram, em qualquer linguagem.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _ciphertexts_to_json(ciphertexts: Sequence[tuple[int, int]]) -> list[dict]:
    # Strings decimais, como no cadastro: leitores JSON de 53 bits (ex.:
    # JavaScript) corromperiam inteiros de 2048 bits.
    return [{"c1": str(c1), "c2": str(c2)} for c1, c2 in ciphertexts]


def _proof_to_json(proof: object) -> str | None:
    """Valida e canoniza a prova opcional. ``None`` significa "sem prova"."""
    if proof is None:
        return None
    if type(proof) is not dict:
        raise InvalidProofError("proof deve ser um objeto JSON (dict)")
    try:
        encoded = _canonical_json(proof)
    except (TypeError, ValueError) as exc:
        raise InvalidProofError("proof não é serializável em JSON canônico") from exc
    if len(encoded) > MAX_PROOF_BYTES:
        raise InvalidProofError("proof grande demais")
    return encoded.decode("ascii")


def ballot_signing_payload(
    election_id: str,
    voter_id: str,
    ciphertexts: Sequence[tuple[int, int]],
    proof: dict | None = None,
) -> bytes:
    """Bytes exatos que o eleitor assina e o servidor verifica.

    Use esta mesma função no cliente do eleitor e no auditor: reimplementar a
    serialização em outro lugar é a forma mais comum de quebrar assinaturas.

    Inclui ``election_id`` (impede reaproveitar a cédula em outra eleição),
    ``voter_id`` (impede que outro eleitor a reivindique), todas as cifras na
    ordem dos candidatos e a prova (retirá-la ou trocá-la invalida a assinatura).
    """
    validate_identifier(election_id, "election_id")
    validate_identifier(voter_id, "voter_id")
    pairs: list[tuple[int, int]] = []
    for pair in ciphertexts:
        if type(pair) not in (tuple, list) or len(pair) != 2:
            raise InvalidBallotError("cada cifra deve ser um par (c1, c2)")
        c1, c2 = pair
        if not (_is_strict_int(c1) and _is_strict_int(c2)):
            raise InvalidBallotError("c1 e c2 devem ser int (bool não é aceito)")
        pairs.append((c1, c2))
    proof_json = _proof_to_json(proof)
    return _canonical_json(
        {
            "type": BALLOT_TYPE,
            "version": BALLOT_VERSION,
            "election_id": election_id,
            "voter_id": voter_id,
            "ciphertexts": _ciphertexts_to_json(pairs),
            "proof": None if proof_json is None else json.loads(proof_json),
        }
    )


def compute_receipt(payload: bytes, signature: str) -> str:
    """Recibo = SHA-256(payload || 0x0A || assinatura base64), em hexadecimal.

    O payload é JSON canônico compacto, sem quebra de linha literal, então o
    separador não é ambíguo. Incluir a assinatura faz o recibo identificar a
    cédula exatamente como foi aceita.
    """
    return hashlib.sha256(payload + b"\n" + signature.encode("ascii")).hexdigest()


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


def _validate_group(group: GroupParams, mod_exp: ModExp) -> None:
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
    if mod_exp(g, q, p) != 1:
        raise ValueError("g não pertence ao subgrupo de ordem q")


def _validate_candidates(candidates: object) -> tuple[str, ...]:
    if isinstance(candidates, (str, bytes)) or not isinstance(candidates, Sequence):
        raise ValueError("candidates deve ser uma lista de nomes")
    names = tuple(candidates)
    if len(names) < MIN_CANDIDATES:
        raise ValueError(f"a eleição exige pelo menos {MIN_CANDIDATES} candidatos")
    for name in names:
        # Espaços internos são permitidos ("Maria Silva"); nas pontas ou
        # caracteres de controle geram nomes visualmente iguais.
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= MAX_CANDIDATE_NAME
            or name != name.strip()
            or not name.isprintable()
        ):
            raise ValueError(f"nome de candidato inválido: {name!r}")
    if len(set(names)) != len(names):
        raise ValueError("candidatos repetidos")
    return names


# ---------------------------------------------------------------------- eleição
class Election:
    """Uma eleição: etapa atual, eleitores habilitados e cédulas aceitas.

    Fluxo típico::

        election = Election("eleicao-2026", group, ["Alice", "Bob"],
                            signature_verifier=verify_signature)
        registration = Registration("eleicao-2026", p=group.p, q=group.q,
                                    state_provider=election.current_state)
        ...  # cadastro de eleitores e autoridades
        registration.freeze()
        public_data = registration.export_public_data()
        publish_joint_public_key(public_data, group, "data/public/election.json")
        election.open_voting(public_data, election_path="data/public/election.json")
        receipt = election.submit_ballot(ballot)
        election.close_voting()
        election.start_tally()   # após a apuração (server/tally.py)
        election.mark_audited()  # após o auditor independente

    Contrato:
    - A construção é a etapa ``CONFIGURACAO`` (grupo e candidatos validados
      aqui); por isso o objeto já nasce em ``CADASTRO``.
    - Transições avançam uma etapa por vez, conforme ``NEXT_STATE``; nunca
      voltam. Cada mudança é persistida antes de ser aplicada em memória.
    - O cadastro é copiado uma única vez, ao abrir a votação.
    - Nenhum método recebe ou devolve chave privada.
    """

    def __init__(
        self,
        election_id: str,
        group: GroupParams,
        candidates: Sequence[str],
        *,
        signature_verifier: SignatureVerifier,
        proof_verifier: ProofVerifier | None = None,
        require_proof: bool = False,
        mod_exp: ModExp | None = None,
        ballots_path: Path | str = DEFAULT_BALLOTS_PATH,
    ) -> None:
        try:
            validate_identifier(election_id, "election_id")
        except InvalidBallotError as exc:
            raise ValueError(str(exc)) from None

        resolved_mod_exp = mod_exp if mod_exp is not None else _default_mod_exp
        if resolved_mod_exp is None:
            raise RuntimeError(
                "src.crypto.group.mod_exp indisponível nesta branch; injete mod_exp=..."
            )
        if not callable(resolved_mod_exp):
            raise TypeError("mod_exp deve ser uma função")
        # Assinatura é obrigatória: aceitar cédulas sem verificá-la permitiria
        # que qualquer um votasse em nome de um eleitor cadastrado.
        if not callable(signature_verifier):
            raise TypeError("signature_verifier deve ser uma função")
        if proof_verifier is not None and not callable(proof_verifier):
            raise TypeError("proof_verifier deve ser uma função")
        if type(require_proof) is not bool:
            raise TypeError("require_proof deve ser bool")
        # Exigir prova sem saber verificá-la rejeitaria toda cédula: erro de
        # configuração que deve aparecer agora, não durante a votação.
        if require_proof and proof_verifier is None:
            raise ValueError("require_proof=True exige um proof_verifier")

        _validate_group(group, resolved_mod_exp)

        self._election_id = election_id
        self._group = group
        self._candidates = _validate_candidates(candidates)
        self._mod_exp = resolved_mod_exp
        self._verify_signature = signature_verifier
        self._verify_proof = proof_verifier
        self._require_proof = require_proof
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
        if not _is_strict_int(h) or not 2 <= h <= p - 1 or self._mod_exp(h, q, p) != 1:
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
        """``ENCERRADA -> APURACAO``. A apuração em si é feita por ``server/tally.py``."""
        self._advance(ElectionState.APURACAO)

    def mark_audited(self) -> None:
        """``APURACAO -> AUDITADA``, após o auditor independente. Etapa terminal."""
        self._advance(ElectionState.AUDITADA)

    # ---------------------------------------------------------------- votação
    def submit_ballot(self, ballot: dict) -> Receipt:
        """Valida e registra uma cédula; devolve o recibo.

        Formato::

            {
              "election_id": "eleicao-2026",
              "voter_id": "eleitor-1",
              "ciphertexts": [{"c1": int, "c2": int}, ...],   # um por candidato
              "signature": "<base64 da assinatura de ballot_signing_payload>",
              "proof": {...}                                   # opcional
            }

        Ordem das verificações (qualquer falha rejeita sem registrar nada):

        1. etapa ``VOTACAO_ABERTA`` (``VotingClosedError``);
        2. estrutura, tipos estritos e intervalo ``[2, p-1]`` (``InvalidBallotError``);
        3. eleitor no cadastro congelado (``IneligibleVoterError``);
        4. eleitor ainda sem voto (``DuplicateVoteError``);
        5. assinatura com a chave cadastrada (``InvalidSignatureError``);
        6. ``c1^q ≡ c2^q ≡ 1 (mod p)`` e ``c1`` sem reuso (``InvalidBallotError``);
        7. prova de validade, se fornecida ou exigida (``InvalidProofError``).

        Checagens baratas vêm primeiro; a exponenciação modular (6) só roda
        para cédulas já autenticadas (5).
        """
        with self._lock:
            if self._state is not ElectionState.VOTACAO_ABERTA:
                raise VotingClosedError(
                    "cédulas só são aceitas em VOTACAO_ABERTA; "
                    f"etapa atual: {self._state.value}"
                )

            parsed = self._parse_ballot(ballot)

            voter_key = self._voters.get(parsed.voter_id)
            if voter_key is None:
                raise IneligibleVoterError(f"eleitor {parsed.voter_id!r} não está habilitado")
            if parsed.voter_id in self._voted:
                # Nada abaixo é executado: o voto original fica intacto.
                raise DuplicateVoteError(f"eleitor {parsed.voter_id!r} já votou")

            payload = ballot_signing_payload(
                self._election_id, parsed.voter_id, parsed.ciphertexts, parsed.proof
            )
            self._check_signature(voter_key, payload, parsed.signature_raw)
            self._check_subgroup(parsed.ciphertexts)
            self._check_proof(parsed.proof, parsed.ciphertexts)

            record = AcceptedBallot(
                index=len(self._ballots),
                voter_id=parsed.voter_id,
                ciphertexts=parsed.ciphertexts,
                proof_json=parsed.proof_json,
                signature=parsed.signature,
                receipt=compute_receipt(payload, parsed.signature),
            )
            new_ballots = self._ballots + (record,)
            # Persiste antes de atualizar a memória: se a escrita falhar, o
            # voto não conta e o eleitor pode reenviar.
            self._persist(self._state, new_ballots, self._joint_public_key)
            self._ballots = new_ballots
            self._voted = self._voted | {parsed.voter_id}
            self._used_c1 = self._used_c1 | {c1 for c1, _ in parsed.ciphertexts}
            return Receipt(record.index, record.voter_id, record.receipt)

    def _parse_ballot(self, ballot: object) -> _ParsedBallot:
        """Validação estrutural; não depende de quem é o eleitor."""
        if type(ballot) is not dict:
            raise InvalidBallotError("a cédula deve ser um dict")
        keys = set(ballot)
        missing = _REQUIRED_FIELDS - keys
        if missing:
            raise InvalidBallotError(f"campos obrigatórios ausentes: {sorted(missing)}")
        # Campos extras não estariam cobertos pela assinatura e poderiam ser
        # contrabandeados para o arquivo público.
        extra = keys - _REQUIRED_FIELDS - _OPTIONAL_FIELDS
        if extra:
            raise InvalidBallotError(f"campos desconhecidos: {sorted(map(repr, extra))}")

        validate_identifier(ballot["election_id"], "election_id")
        if ballot["election_id"] != self._election_id:
            raise InvalidBallotError("a cédula pertence a outra eleição")
        voter_id = validate_identifier(ballot["voter_id"], "voter_id")
        ciphertexts = self._parse_ciphertexts(ballot["ciphertexts"])
        signature = ballot["signature"]
        signature_raw = _decode_signature(signature)
        proof = ballot.get("proof")
        proof_json = _proof_to_json(proof)
        return _ParsedBallot(voter_id, ciphertexts, signature, signature_raw, proof, proof_json)

    def _parse_ciphertexts(self, raw: object) -> tuple[tuple[int, int], ...]:
        if type(raw) not in (list, tuple):
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
            if type(item) is not dict or set(item) != {"c1", "c2"}:
                raise InvalidBallotError(f"cifra {position} deve ter exatamente c1 e c2")
            c1, c2 = item["c1"], item["c2"]
            for name, value in (("c1", c1), ("c2", c2)):
                if not _is_strict_int(value):
                    raise InvalidBallotError(f"{name} da cifra {position} deve ser int")
                # c1 = 1 significaria r = 0, e então c2 = g^m revelaria o voto.
                # Valores >= p não estão reduzidos e dariam várias
                # representações da mesma cifra.
                if not 2 <= value <= p - 1:
                    raise InvalidBallotError(f"{name} da cifra {position} fora de [2, p-1]")
            pairs.append((c1, c2))
        c1_values = [c1 for c1, _ in pairs]
        # Mesmo c1 em duas cifras = mesmo r: c2/c2' = g^(m-m') revelaria se os
        # votos são iguais.
        if len(set(c1_values)) != len(c1_values):
            raise InvalidBallotError("c1 repetido dentro da cédula (aleatoriedade reutilizada)")
        return tuple(pairs)

    def _check_signature(self, voter_key: str, payload: bytes, signature: bytes) -> None:
        # A chave vem SEMPRE do cadastro congelado, nunca da cédula: uma cédula
        # assinada por terceiros não passa, mesmo que traga uma chave própria.
        try:
            valid = self._verify_signature(voter_key, payload, signature)
        except Exception as exc:
            # Qualquer falha do verificador é tratada como assinatura inválida:
            # rejeitar é o lado seguro.
            raise InvalidSignatureError("assinatura inválida") from exc
        # "is True": um verificador que devolva 1, "ok" ou um objeto não passa.
        if valid is not True:
            raise InvalidSignatureError("assinatura inválida")

    def _check_subgroup(self, ciphertexts: tuple[tuple[int, int], ...]) -> None:
        p, q = self._group.p, self._group.q
        for position, (c1, c2) in enumerate(ciphertexts):
            # Elementos fora do subgrupo (ex.: p-1 ou não-resíduo quadrático)
            # podem vazar um bit do voto e quebrar a soma homomórfica.
            if self._mod_exp(c1, q, p) != 1 or self._mod_exp(c2, q, p) != 1:
                raise InvalidBallotError(f"cifra {position} fora do subgrupo de ordem q")
            # Copiar a cifra de outro eleitor replicaria o voto dele sem
            # conhecê-lo; reusar r vaza a relação entre os votos.
            if c1 in self._used_c1:
                raise InvalidBallotError(f"c1 da cifra {position} já usado em outra cédula")

    def _check_proof(self, proof: dict | None, ciphertexts: tuple[tuple[int, int], ...]) -> None:
        if proof is None:
            if self._require_proof:
                raise InvalidProofError("esta eleição exige prova de validade do voto")
            return
        if self._verify_proof is None:
            # Aceitar prova sem verificá-la daria uma falsa garantia.
            raise InvalidProofError("prova fornecida, mas nenhum verificador está configurado")
        try:
            # deepcopy: o verificador não consegue alterar a prova registrada.
            valid = self._verify_proof(
                copy.deepcopy(proof), ciphertexts, self._group, self._joint_public_key
            )
        except Exception as exc:
            raise InvalidProofError("prova de validade inválida") from exc
        if valid is not True:
            raise InvalidProofError("prova de validade inválida")

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