"""Ciclo de vida da eleição, elegibilidade e validação das cédulas.

API pública do pacote:

- ``src.election.states``: etapas oficiais (``ElectionState``), transições
  permitidas (``NEXT_STATE``) e erros de transição.
- ``src.election.election``: ``Election``, cédulas, recibos e erros de voto.

O contrato completo (o que cada módulo faz e o que NÃO faz) está nas
docstrings desses módulos. Todos os nomes exportados antes continuam
disponíveis aqui e em ``src.election.election``.
"""

from src.election.election import (
    BALLOT_TYPE,
    BALLOT_VERSION,
    BALLOTS_SCHEMA_VERSION,
    DEFAULT_BALLOTS_PATH,
    IDENTIFIER_PATTERN,
    MAX_PROOF_BYTES,
    MAX_SIGNATURE_BYTES,
    MIN_AUTHORITIES,
    MIN_CANDIDATES,
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
    ballot_signing_payload,
    compute_receipt,
    validate_identifier,
)
from src.election.states import (
    NEXT_STATE,
    ElectionError,
    ElectionState,
    ElectionStateError,
    InvalidStateTransitionError,
    VotingPreconditionError,
)

__all__ = [
    # states
    "NEXT_STATE",
    "ElectionError",
    "ElectionState",
    "ElectionStateError",
    "InvalidStateTransitionError",
    "VotingPreconditionError",
    # election
    "BALLOT_TYPE",
    "BALLOT_VERSION",
    "BALLOTS_SCHEMA_VERSION",
    "DEFAULT_BALLOTS_PATH",
    "IDENTIFIER_PATTERN",
    "MAX_PROOF_BYTES",
    "MAX_SIGNATURE_BYTES",
    "MIN_AUTHORITIES",
    "MIN_CANDIDATES",
    "AcceptedBallot",
    "DuplicateVoteError",
    "Election",
    "IneligibleVoterError",
    "InvalidBallotError",
    "InvalidProofError",
    "InvalidSignatureError",
    "Receipt",
    "VoteRejectedError",
    "VotingClosedError",
    "ballot_signing_payload",
    "compute_receipt",
    "validate_identifier",
]