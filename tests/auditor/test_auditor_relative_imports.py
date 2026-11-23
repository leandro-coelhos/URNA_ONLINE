"""Imports RELATIVOS em ``src/auditor/`` (complementa o teste AST do auditor).

``test_auditor.py::test_auditor_imports_only_crypto_and_bulletin_board``
confere só nomes que começam com ``src``. Num import relativo o AST guarda
o nome SEM o pacote (``from ..server import voting`` vira ``module="server"``,
``level=2``), então esse teste não o vê. Este arquivo fecha a lacuna sem
alterar o teste original:

- ``level >= 2`` (subir para ``src`` e entrar em outro pacote) é recusado;
- ``level == 1`` só é aceito para módulos que existem em ``src/auditor/``
  (hoje, ``from .board_tally import ...`` em ``auditor.py``).
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDITOR_DIR = ROOT / "src" / "auditor"


def _local_modules() -> set:
    """Módulos e subpacotes que existem em ``src/auditor/``."""
    names = {path.stem for path in AUDITOR_DIR.glob("*.py")}
    names |= {path.name for path in AUDITOR_DIR.iterdir()
              if path.is_dir() and (path / "__init__.py").exists()}
    return names


def relative_import_violations(source: str, local: set, filename: str = "<texto>") -> list:
    """Motivos de recusa dos imports relativos de ``source`` (lista vazia = ok)."""
    violations = []
    for node in ast.walk(ast.parse(source, filename=filename)):
        if not isinstance(node, ast.ImportFrom) or node.level == 0:
            continue
        shown = "." * node.level + (node.module or "")
        if node.level >= 2:
            violations.append(f"{filename}: import relativo sai de src/auditor/ ({shown})")
            continue
        # "from .x import y" importa o módulo x; "from . import x, z", os módulos x e z.
        targets = [node.module.split(".")[0]] if node.module else [a.name for a in node.names]
        for target in targets:
            if target not in local:
                violations.append(
                    f"{filename}: import relativo de módulo inexistente em src/auditor/ ({shown} -> {target})"
                )
    return violations


def test_auditor_relative_imports_stay_inside_the_package():
    local = _local_modules()
    assert "board_tally" in local
    violations = []
    for path in sorted(AUDITOR_DIR.glob("*.py")):
        violations += relative_import_violations(path.read_text(encoding="utf-8"), local, path.name)
    assert not violations, "\n".join(violations)


def test_relative_import_rule_rejects_parent_packages_and_unknown_modules():
    """A regra em si: o que é aceito e o que é recusado."""
    local = _local_modules()
    accepted = [
        "from .board_tally import record_ciphertexts",
        "from . import board_tally",
        "from .auditor import Auditor",
    ]
    rejected = [
        "from ..server import voting",
        "from ..authorities.partial_decryption import build_aggregate",
        "from .. import server",
        "from ...src import server",
        "from .inexistente import algo",
        "from . import board_tally, inexistente",
    ]
    for source in accepted:
        assert relative_import_violations(source, local) == [], source
    for source in rejected:
        assert relative_import_violations(source, local), source
