"""Auditor independente: verifica a eleição usando somente ``data/public/``.

Importa apenas ``src.crypto`` e ``src.bulletin_board``; não importa
``src.server``, ``src.election`` nem ``src.authorities`` e não lê
``data/private/``. A implementação e a API estão em ``src.auditor.auditor``;
execução: ``python -m src.cli.main auditar <dir público>`` (CLI) ou
``python -m src.auditor.auditor <dir público>``.
"""
