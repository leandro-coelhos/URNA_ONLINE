"""Camada de serviço do servidor para a etapa de votação.

O que este módulo FAZ
---------------------
- Expõe ao servidor e à CLI uma interface curta sobre
  ``src.election.election.Election``: ``open_voting``, ``receive_ballot`` e
  ``close_voting``, além de ``current_state``/``state``.
- Monta a ``Election`` quando recebe só os parâmetros e, se nenhum
  ``signature_verifier`` for passado, procura ``verify_signature`` em
  ``src.server.validation`` e depois em ``src.crypto.signatures``.
- Publica cada cédula ACEITA no quadro público por meio do callback
  ``board_publisher``, na ordem exata de aceitação e uma única vez cada.
- Reexporta as exceções de estado e de rejeição, para que
  ``src/cli/main.py`` importe tudo de ``src.server.voting``.

O que este módulo NÃO FAZ
-------------------------
- Não duplica regras da eleição: estados, elegibilidade, voto único,
  assinatura, subgrupo, prova e persistência continuam em ``Election``.
  Toda cédula passa por ``Election.submit_ballot``; rejeições propagam sem
  alteração e nunca chegam ao quadro.
- Não implementa primitivas criptográficas nem verificação de assinatura:
  apenas localiza e repassa o verificador.
- Não implementa o quadro público nem a cadeia de hashes
  (``src.bulletin_board``): só chama o callback injetado.
- Nunca recebe, lê ou guarda chaves privadas.

Falha do quadro público
-----------------------
Quando ``board_publisher`` falha, a cédula já foi aceita e persistida por
``Election``: o voto CONTA. O serviço lança ``BoardPublicationError`` com o
recibo, mantém a cédula na fila ``pending_publications`` e tenta publicá-la
de novo (primeiro, para preservar a ordem) no próximo ``receive_ballot`` ou
em ``publish_pending()``. Enquanto houver pendência que não consiga ser
publicada, nenhuma cédula nova é aceita, para que o quadro nunca fique fora
de ordem.
"""

from __future__ import annotations

import importlib
import threading
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from src.election.election import (
    AcceptedBallot,
    DuplicateVoteError,
    Election,
    IneligibleVoterError,
    InvalidBallotError,
    InvalidProofError,
    InvalidSignatureError,
    ModExp,
    ProofVerifier,
    Receipt,
    SignatureVerifier,
    VoteRejectedError,
    VotingClosedError,
)
from src.election.states import (
    ElectionError,
    ElectionState,
    ElectionStateError,
    InvalidStateTransitionError,
    VotingPreconditionError,
)

__all__ = [
    "DEFAULT_SIGNATURE_VERIFIER_SOURCES",
    "BoardPublicationError",
    "BoardPublisher",
    "VotingService",
    "load_default_signature_verifier",
    # Reexportados para a CLI:
    "AcceptedBallot",
    "DuplicateVoteError",
    "ElectionError",
    "ElectionState",
    "ElectionStateError",
    "IneligibleVoterError",
    "InvalidBallotError",
    "InvalidProofError",
    "InvalidSignatureError",
    "InvalidStateTransitionError",
    "Receipt",
    "VoteRejectedError",
    "VotingClosedError",
    "VotingPreconditionError",
]

# Callback do quadro público: recebe a cédula aceita (imutável). O retorno é
# ignorado; qualquer exceção vira BoardPublicationError.
BoardPublisher = Callable[[AcceptedBallot], Any]

# Onde procurar o verificador padrão, em ordem de preferência. O validador do
# servidor vem primeiro porque pode adaptar a interface do módulo de crypto.
DEFAULT_SIGNATURE_VERIFIER_SOURCES = ("src.server.validation", "src.crypto.signatures")
_SIGNATURE_VERIFIER_NAME = "verify_signature"


class BoardPublicationError(RuntimeError):
    """O quadro público não aceitou uma cédula já aceita pela eleição.

    Não é uma rejeição de voto (por isso não herda de ``ElectionError``).

    - ``receipt``: recibo da cédula aceita NESTA chamada, ou ``None`` se a
      falha ocorreu ao publicar uma pendência anterior, antes de processar a
      cédula nova (que, nesse caso, não foi registrada).
    - ``ballot``: a cédula que não pôde ser publicada; continua pendente.
    """

    def __init__(self, message: str, *, receipt: Receipt | None, ballot: AcceptedBallot) -> None:
        super().__init__(message)
        self.receipt = receipt
        self.ballot = ballot


def load_default_signature_verifier() -> SignatureVerifier | None:
    """Procura ``verify_signature`` nos módulos de ``DEFAULT_SIGNATURE_VERIFIER_SOURCES``.

    Devolve o primeiro que existir e for chamável, ou ``None``. Um módulo
    ausente na branch (``ImportError``) é ignorado; qualquer outro erro de
    importação propaga, pois indica código quebrado e não ausência.
    """
    for module_name in DEFAULT_SIGNATURE_VERIFIER_SOURCES:
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        verifier = getattr(module, _SIGNATURE_VERIFIER_NAME, None)
        if callable(verifier):
            return verifier
    return None


class VotingService:
    """Serviço de votação do servidor, apoiado em uma ``Election``.

    Duas formas de construir (mutuamente exclusivas)::

        VotingService(election, board_publisher=board.append)

        VotingService(election_id="eleicao-2026", group=group,
                      candidates=["Alice", "Bob"],
                      board_publisher=board.append)  # verificador padrão

    Contrato:
    - ``receive_ballot`` só devolve o ``Receipt`` depois que a cédula foi
      aceita pela eleição E publicada no quadro (quando há quadro).
    - Cédulas rejeitadas nunca chegam ao ``board_publisher``.
    - O quadro recebe as cédulas na ordem de ``Election.accepted_ballots``,
      cada uma exatamente uma vez.
    """

    def __init__(
        self,
        election: Election | None = None,
        *,
        board_publisher: BoardPublisher | None = None,
        election_id: str | None = None,
        group: Any = None,
        candidates: Sequence[str] | None = None,
        signature_verifier: SignatureVerifier | None = None,
        proof_verifier: ProofVerifier | None = None,
        require_proof: bool = False,
        mod_exp: ModExp | None = None,
        ballots_path: Path | str | None = None,
    ) -> None:
        if board_publisher is not None and not callable(board_publisher):
            raise TypeError("board_publisher deve ser uma função")

        if election is not None:
            if not isinstance(election, Election):
                raise TypeError("election deve ser uma instância de Election")
            # Misturar as duas formas deixaria ambíguo qual configuração vale.
            build_args = (election_id, group, candidates, signature_verifier,
                          proof_verifier, mod_exp, ballots_path)
            if any(arg is not None for arg in build_args) or require_proof:
                raise ValueError("passe uma Election pronta OU os parâmetros para criá-la")
        else:
            if election_id is None or group is None or candidates is None:
                raise TypeError("sem election, informe election_id, group e candidates")
            if signature_verifier is None:
                signature_verifier = load_default_signature_verifier()
            if signature_verifier is None:
                # Nunca há verificação "vazia": sem verificador, não há eleição.
                raise RuntimeError(
                    "nenhum verificador de assinatura disponível nesta branch "
                    f"({', '.join(DEFAULT_SIGNATURE_VERIFIER_SOURCES)}); "
                    "injete signature_verifier=..."
                )
            extra = {} if ballots_path is None else {"ballots_path": ballots_path}
            election = Election(
                election_id,
                group,
                candidates,
                signature_verifier=signature_verifier,
                proof_verifier=proof_verifier,
                require_proof=require_proof,
                mod_exp=mod_exp,
                **extra,
            )

        # Cédulas aceitas antes do serviço não passaram por este quadro; com
        # quadro configurado, a cadeia ficaria incompleta sem aviso.
        if board_publisher is not None and election.accepted_ballots:
            raise ValueError("a eleição já tem cédulas que não foram publicadas por este serviço")

        self._election = election
        self._board_publisher = board_publisher
        # Quantas cédulas de accepted_ballots já foram publicadas, em ordem.
        self._published_count = len(election.accepted_ballots)
        # Uma trava do serviço garante que publicação e aceitação não se
        # intercalem entre chamadas concorrentes (a ordem do quadro importa).
        self._lock = threading.RLock()

    # -------------------------------------------------------------- consultas
    @property
    def election(self) -> Election:
        return self._election

    @property
    def state(self) -> ElectionState:
        return self._election.state

    def current_state(self) -> str:
        """Etapa atual como string; serve de ``state_provider`` ao ``Registration``."""
        return self._election.current_state()

    @property
    def accepted_ballots(self) -> tuple[AcceptedBallot, ...]:
        return self._election.accepted_ballots

    def has_voted(self, voter_id: str) -> bool:
        return self._election.has_voted(voter_id)

    @property
    def pending_publications(self) -> tuple[AcceptedBallot, ...]:
        """Cédulas aceitas que o quadro público ainda não recebeu."""
        if self._board_publisher is None:
            return ()
        return self._election.accepted_ballots[self._published_count:]

    # ------------------------------------------------------------- transições
    def open_voting(self, public_data: dict, *, election_path: Path | str | None = None) -> None:
        """``CADASTRO -> VOTACAO_ABERTA``; pré-condições verificadas por ``Election``."""
        with self._lock:
            self._election.open_voting(public_data, election_path=election_path)

    def close_voting(self) -> None:
        """``VOTACAO_ABERTA -> ENCERRADA``.

        Não depende do quadro: se ele estiver fora do ar, o encerramento no
        horário previsto não pode ser impedido. Pendências continuam em
        ``pending_publications`` e podem ser enviadas com ``publish_pending``.
        """
        with self._lock:
            self._election.close_voting()

    # ---------------------------------------------------------------- votação
    def receive_ballot(self, ballot: dict) -> Receipt:
        """Recebe uma cédula, registra via ``Election.submit_ballot`` e publica no quadro.

        Propaga sem alteração ``VotingClosedError``, ``IneligibleVoterError``,
        ``DuplicateVoteError``, ``InvalidBallotError``,
        ``InvalidSignatureError`` e ``InvalidProofError``; nesses casos o
        quadro não é chamado. Lança ``BoardPublicationError`` se o quadro
        falhar (veja a docstring do módulo).
        """
        with self._lock:
            # 1) Pendências primeiro: o quadro não pode receber a cédula n+1
            #    antes da n. Se falhar, a cédula nova nem é processada.
            self._flush_pending(receipt=None)

            # 2) Todas as regras ficam em Election; rejeições propagam daqui.
            receipt = self._election.submit_ballot(ballot)

            # 3) Defesa contra inconsistência: sob a trava, a última cédula
            #    aceita tem de ser exatamente a deste recibo.
            record = self._election.accepted_ballots[-1]
            if record.index != receipt.index or record.receipt != receipt.receipt:
                raise RuntimeError("inconsistência entre recibo e cédula aceita")

            # 4) Publica a cédula recém-aceita (e qualquer resto da fila).
            self._flush_pending(receipt=receipt)
            return receipt

    def publish_pending(self) -> int:
        """Tenta publicar as pendências, em ordem; devolve quantas foram publicadas.

        Pode ser chamado em qualquer etapa (inclusive após o encerramento).
        """
        with self._lock:
            before = self._published_count
            self._flush_pending(receipt=None)
            return self._published_count - before

    def _flush_pending(self, *, receipt: Receipt | None) -> None:
        ballots = self._election.accepted_ballots
        if self._board_publisher is None:
            self._published_count = len(ballots)
            return
        while self._published_count < len(ballots):
            record = ballots[self._published_count]
            try:
                self._board_publisher(record)
            except Exception as exc:
                # O contador só avança após sucesso: a cédula continua pendente
                # e será a primeira da próxima tentativa.
                raise BoardPublicationError(
                    f"falha ao publicar a cédula {record.index} no quadro público",
                    receipt=receipt,
                    ballot=record,
                ) from exc
            self._published_count += 1