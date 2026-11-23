"""Etapas oficiais da eleição e erros de transição.

Define as seis etapas da eleição, na única ordem permitida::

    CONFIGURACAO -> CADASTRO -> VOTACAO_ABERTA -> ENCERRADA -> APURACAO -> AUDITADA

O que este módulo FAZ
---------------------
- Declara ``ElectionState``, cujos valores são as strings oficiais do README.
  ``src.server.registration.Registration`` reconhece exatamente essas strings:
  libera inclusões só em ``"CADASTRO"`` e se congela sozinho ao ver
  ``"VOTACAO_ABERTA"``, ``"ENCERRADA"``, ``"APURACAO"`` ou ``"AUDITADA"``.
- Declara ``NEXT_STATE``: cada etapa tem exatamente uma sucessora, não existe
  aresta para trás nem atalho, e ``AUDITADA`` é terminal.
- Declara a base de erros da eleição e os erros de transição.

O que este módulo NÃO FAZ
-------------------------
- Não guarda a etapa atual nem executa transições: isso é papel de
  ``src.election.election.Election``, que valida as pré-condições e persiste
  cada mudança antes de aplicá-la.
"""

from __future__ import annotations

import enum
from types import MappingProxyType


# ------------------------------------------------------------------------ erros
class ElectionError(ValueError):
    """Base dos erros da eleição; herda de ``ValueError`` como ``RegistrationError``."""


class ElectionStateError(ElectionError):
    """Operação incompatível com a etapa atual."""


class InvalidStateTransitionError(ElectionStateError):
    """Retrocesso, salto de etapa ou repetição de uma transição já feita."""


class VotingPreconditionError(InvalidStateTransitionError):
    """``CADASTRO -> VOTACAO_ABERTA`` recusada: cadastro, autoridades ou chave inválidos.

    É uma transição inválida, por isso herda de ``InvalidStateTransitionError``.
    """


# ---------------------------------------------------------------------- estados
class ElectionState(str, enum.Enum):
    """Etapas oficiais da eleição. O valor é a string usada pelo cadastro.

    A ordem de declaração é a ordem do ciclo; ``list(ElectionState)`` devolve a
    sequência completa.
    """

    CONFIGURACAO = "CONFIGURACAO"
    CADASTRO = "CADASTRO"
    VOTACAO_ABERTA = "VOTACAO_ABERTA"
    ENCERRADA = "ENCERRADA"
    APURACAO = "APURACAO"
    AUDITADA = "AUDITADA"


# MappingProxyType: visão somente leitura. Nenhum módulo consegue acrescentar,
# por engano ou de propósito, uma aresta para trás (ex.: ENCERRADA -> CADASTRO).
NEXT_STATE = MappingProxyType(
    {
        ElectionState.CONFIGURACAO: ElectionState.CADASTRO,
        ElectionState.CADASTRO: ElectionState.VOTACAO_ABERTA,
        ElectionState.VOTACAO_ABERTA: ElectionState.ENCERRADA,
        ElectionState.ENCERRADA: ElectionState.APURACAO,
        ElectionState.APURACAO: ElectionState.AUDITADA,
    }
)