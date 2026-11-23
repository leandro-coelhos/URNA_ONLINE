"""Camada de serviço do servidor para a etapa de votação.

O que este módulo FAZ
---------------------
- Expõe ao servidor (e a quem o conduz, como ``demo.py`` e os testes) uma
  interface curta sobre ``src.election.election.Election``: ``open_voting``,
  ``receive_ballot`` e ``close_voting``, além de ``current_state``/``state``.
- Monta a ``Election`` quando recebe só os parâmetros.
- Recebe somente o envelope de ``src.crypto.ballots`` (o único formato de
  cédula), que a ``Election`` valida e autentica.
- Publica cada cédula ACEITA no quadro público por meio do callback
  ``board_publisher``, na ordem exata de aceitação e uma única vez cada. O
  callback recebe a ``AcceptedBallot``; com o quadro real, use
  ``board_publisher_for(board)``, que entrega ``record.envelope()`` a
  ``BulletinBoard.append`` (que reverifica a assinatura).
- Reexporta as exceções de estado e de rejeição, para que quem usa o serviço
  importe tudo de ``src.server.voting``.

O que este módulo NÃO FAZ
-------------------------
- Não duplica regras da eleição: estados, elegibilidade, voto único,
  assinatura, subgrupo, prova e persistência continuam em ``Election``.
  Toda cédula passa por ``Election.submit_ballot``; rejeições propagam sem
  alteração e nunca chegam ao quadro.
- Não implementa primitivas criptográficas nem verificação de assinatura:
  isso é feito pela ``Election`` com ``src.crypto.ballots``, sem verificador
  injetável (não há como desativar a verificação).
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
    Receipt,
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
    "BoardPublicationError",
    "BoardPublisher",
    "VotingService",
    "board_publisher_for",
    # Reexportados para quem usa o serviço:
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


def board_publisher_for(board: Any) -> BoardPublisher:
    """Callback que publica no quadro real (``src.bulletin_board.board.BulletinBoard``).

    Entrega ao ``board.append`` o envelope exato da cédula aceita e devolve o
    registro público gravado (índice, ``previous_hash``, ``hash``). Não
    importa o módulo do quadro: recebe a instância já aberta.
    """
    append = getattr(board, "append", None)
    if not callable(append):
        raise TypeError("board deve expor append(envelope)")

    def publish(record: AcceptedBallot) -> Any:
        return append(record.envelope())

    return publish


class VotingService:
    """Serviço de votação do servidor, apoiado em uma ``Election``.

    Duas formas de construir (mutuamente exclusivas)::

        VotingService(election, board_publisher=board_publisher_for(board))

        VotingService(election_id="eleicao-2026", group=group,
                      candidates=["Alice", "Bob"],
                      board_publisher=board_publisher_for(board))

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
        ballots_path: Path | str | None = None,
    ) -> None:
        if board_publisher is not None and not callable(board_publisher):
            raise TypeError("board_publisher deve ser uma função")

        if election is not None:
            if not isinstance(election, Election):
                raise TypeError("election deve ser uma instância de Election")
            # Misturar as duas formas deixaria ambíguo qual configuração vale.
            build_args = (election_id, group, candidates, ballots_path)
            if any(arg is not None for arg in build_args):
                raise ValueError("passe uma Election pronta OU os parâmetros para criá-la")
        else:
            if election_id is None or group is None or candidates is None:
                raise TypeError("sem election, informe election_id, group e candidates")
            extra = {} if ballots_path is None else {"ballots_path": ballots_path}
            election = Election(election_id, group, candidates, **extra)

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
    def receive_ballot(self, envelope: dict) -> Receipt:
        """Recebe um envelope de ``src.crypto.ballots``, registra via
        ``Election.submit_ballot`` e publica no quadro.

        Propaga sem alteração ``VotingClosedError``, ``IneligibleVoterError``,
        ``DuplicateVoteError``, ``InvalidBallotError`` e
        ``InvalidSignatureError``; nesses casos o quadro não é chamado. Lança ``BoardPublicationError`` se o quadro
        falhar (veja a docstring do módulo).
        """
        with self._lock:
            # 1) Pendências primeiro: o quadro não pode receber a cédula n+1
            #    antes da n. Se falhar, a cédula nova nem é processada.
            self._flush_pending(receipt=None)

            # 2) Todas as regras ficam em Election; rejeições propagam daqui.
            receipt = self._election.submit_ballot(envelope)

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