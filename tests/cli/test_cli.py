"""Testes da CLI enxuta ``python -m src.cli.main`` (``src/cli/main.py``).

A CLI só escolhe o subcomando (``demo`` ou ``auditar``), repassa o RESTO dos
argumentos sem interpretá-los para ``demo.main`` ou ``src.auditor.auditor.main``
e devolve o código de saída recebido. O que é conferido aqui:

- delegação: argumentos repassados exatamente e códigos devolvidos sem
  alteração (com ``monkeypatch`` nos dois ``main``);
- erro de uso -> 64 (``EX_USAGE``) na CLI, na demo e no auditor, direto e
  via CLI, em processo e como processo separado;
- ``--help`` da CLI e ``demo --help``: saem com 0 e citam as seis etapas da
  especificação, com o mesmo mapeamento de ``demo.SPEC_STAGES``;
- não duplicação (AST): ``src/cli/`` só importa a biblioteca padrão, ``demo``
  e ``src.auditor.auditor``;
- imports tardios e independência de ``fcntl`` em ``auditar`` (simulando o
  Windows nativo com ``sys.modules["fcntl"] = None``);
- ponta a ponta (exige ``fcntl``): ``demo`` em ``tmp_path`` e ``auditar`` sobre
  ``public/`` (0) e ``tampered_public/`` (1) gerados por ela.

Nada é escrito em ``data/`` do repositório: a demo grava em ``tmp_path``.
"""

import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import demo  # noqa: E402
import src.cli.main as cli  # noqa: E402
from src.auditor import auditor as auditor_mod  # noqa: E402

CLI_DIR = ROOT / "src" / "cli"
CLI_PROG = "python -m src.cli.main"
NO_FCNTL = "src.bulletin_board.board usa fcntl: o quadro público real exige Linux, macOS ou WSL"

STAGE_NAMES = ("configuração", "cadastro de eleitores", "votação", "encerramento",
               "apuração", "auditoria")
# Mapeamento da especificação -> etapas da demo, conferido contra demo.STEPS.
EXPECTED_SPEC_STAGES = (
    ("configuração", (1,)),
    ("cadastro de eleitores", (2,)),
    ("votação", (3, 4)),
    ("encerramento", (5,)),
    ("apuração", (6, 7)),
    ("auditoria", (8, 9)),
)

# Executa a CLI num processo com fcntl indisponível (como no Windows nativo).
RUN_CLI_WITHOUT_FCNTL = (
    "import runpy, sys\n"
    "sys.modules['fcntl'] = None\n"
    "runpy.run_module('src.cli.main', run_name='__main__', alter_sys=True)\n"
)


def _python(*args, timeout=180):
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout, env=env)


def _forbid(monkeypatch):
    """Faz qualquer delegação falhar: para conferir que erros de uso não chegam aos ``main``."""
    def boom(*args, **kwargs):
        raise AssertionError("a CLI não deveria ter delegado")
    monkeypatch.setattr(demo, "main", boom)
    monkeypatch.setattr(auditor_mod, "main", boom)


# =============================================================================
# Delegação
# =============================================================================
REST = ["--pause", "--output-dir", "dir com espaço", "--opcao-que-nao-existe", "--", "-h"]


@pytest.mark.parametrize("code", [0, 1, 2, 3, 64, 130])
def test_demo_receives_exactly_the_remaining_args_and_its_code_is_returned(monkeypatch, code):
    calls = []

    def fake_main(argv=None, *, prog=None):
        calls.append((argv, prog))
        return code

    monkeypatch.setattr(demo, "main", fake_main)
    assert cli.main(["demo", *REST]) == code
    assert calls == [(REST, f"{CLI_PROG} demo")]
    assert type(calls[0][0]) is list


@pytest.mark.parametrize("code", [0, 1, 2, 64])
def test_auditar_receives_exactly_the_remaining_args_and_its_code_is_returned(monkeypatch, code):
    calls = []

    def fake_main(argv=None, *, prog=None):
        calls.append((argv, prog))
        return code

    monkeypatch.setattr(auditor_mod, "main", fake_main)
    rest = ["data/demo/public", "--json", "--extra"]
    assert cli.main(["auditar", *rest]) == code
    assert calls == [(rest, f"{CLI_PROG} auditar")]


@pytest.mark.parametrize("command,module", [("demo", demo), ("auditar", auditor_mod)])
def test_subcommand_without_args_passes_an_empty_list(monkeypatch, command, module):
    calls = []
    monkeypatch.setattr(module, "main", lambda argv=None, *, prog=None: calls.append(argv) or 0)
    assert cli.main([command]) == 0
    assert calls == [[]]


def test_main_without_argv_reads_sys_argv(monkeypatch):
    calls = []
    monkeypatch.setattr(demo, "main", lambda argv=None, *, prog=None: calls.append(argv) or 1)
    monkeypatch.setattr(sys, "argv", ["src/cli/main.py", "demo", "--pause"])
    assert cli.main() == 1
    assert calls == [["--pause"]]


def test_missing_fcntl_via_cli_returns_3_and_creates_nothing(tmp_path, monkeypatch, capsys):
    # demo.main real; simula o Windows nativo.
    monkeypatch.setattr(demo, "fcntl_available", lambda: False)
    output = tmp_path / "saida"
    assert cli.main(["demo", "--output-dir", str(output)]) == demo.EXIT_NO_FCNTL == 3
    err = capsys.readouterr().err
    assert "fcntl" in err and "WSL" in err
    # Orientação neutra: um "wsl -- python3 ..." rodaria sem o ambiente virtual.
    assert "ambiente virtual ativo: python -m src.cli.main demo" in err
    assert "wsl --" not in err and "python3" not in err
    assert not output.exists()


# =============================================================================
# Erros de uso -> 64
# =============================================================================
def test_usage_exit_code_is_64_everywhere_and_unambiguous():
    assert cli.EXIT_USAGE == demo.EXIT_USAGE == auditor_mod.EXIT_USAGE == 64
    demo_codes = {demo.EXIT_OK, demo.EXIT_DIVERGED, demo.EXIT_BAD_OUTPUT_DIR,
                  demo.EXIT_NO_FCNTL, demo.EXIT_INTERRUPTED}
    assert demo.EXIT_USAGE not in demo_codes
    assert auditor_mod.EXIT_USAGE not in {0, 1, 2}  # válida, inválida, erro de configuração


def test_cli_without_subcommand_prints_help_to_stderr_and_exits_64(monkeypatch, capsys):
    _forbid(monkeypatch)
    assert cli.main([]) == 64
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "uso:" in captured.err and "demo" in captured.err and "auditar" in captured.err
    assert "informe um subcomando" in captured.err


@pytest.mark.parametrize("argv,message", [
    (["votar"], "subcomando desconhecido: 'votar'"),
    (["Demo"], "subcomando desconhecido: 'Demo'"),
    (["--verbose"], "opção desconhecida antes do subcomando: '--verbose'"),
    (["--pause", "demo"], "opção desconhecida antes do subcomando: '--pause'"),
], ids=["subcomando", "maiusculas", "opcao", "opcao-antes-do-subcomando"])
def test_cli_unknown_subcommand_or_option_exits_64(monkeypatch, capsys, argv, message):
    _forbid(monkeypatch)
    assert cli.main(argv) == 64
    captured = capsys.readouterr()
    assert captured.out == ""
    assert message in captured.err and "uso:" in captured.err


@pytest.mark.parametrize("argv", [["--opcao-invalida"], ["--output-dir"], ["--pause=sim"]],
                         ids=["opcao-invalida", "sem-valor", "valor-em-flag"])
def test_demo_invalid_option_exits_64_directly_and_via_cli(capsys, argv):
    assert demo.main(argv) == 64
    assert "erro:" in capsys.readouterr().err
    assert cli.main(["demo", *argv]) == 64
    err = capsys.readouterr().err
    assert f"usage: {CLI_PROG} demo" in err and "erro:" in err


@pytest.mark.parametrize("argv", [["--opcao-invalida"], ["dir1", "dir2"]],
                         ids=["opcao-invalida", "dois-diretorios"])
def test_auditor_invalid_option_exits_64_directly_and_via_cli(capsys, argv):
    assert auditor_mod.main(argv) == 64
    assert "erro:" in capsys.readouterr().err
    assert cli.main(["auditar", *argv]) == 64
    err = capsys.readouterr().err
    assert f"usage: {CLI_PROG} auditar" in err and "erro:" in err


@pytest.mark.parametrize("args", [
    ("-m", "src.cli.main"),
    ("-m", "src.cli.main", "votar"),
    ("-m", "src.cli.main", "demo", "--opcao-invalida"),
    ("-m", "src.cli.main", "auditar", "--opcao-invalida"),
    ("demo.py", "--opcao-invalida"),
    ("-m", "src.auditor.auditor", "--opcao-invalida"),
], ids=["cli-sem-subcomando", "cli-subcomando-desconhecido", "cli-demo", "cli-auditar",
        "demo.py", "auditor"])
def test_usage_errors_exit_64_as_separate_process(args):
    proc = _python(*args, timeout=60)
    assert proc.returncode == 64, proc.stderr
    assert proc.stdout == ""
    assert "Traceback" not in proc.stderr


# =============================================================================
# Ajuda e cobertura da especificação
# =============================================================================
@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_cli_help_lists_subcommands_with_example_and_the_six_stages(monkeypatch, capsys, flag):
    _forbid(monkeypatch)
    assert cli.main([flag]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    out = captured.out
    for command in ("demo", "auditar"):
        assert re.search(rf"^  {command}\s+\S", out, re.MULTILINE), command  # linha de descrição
        assert f"ex.: {CLI_PROG} {command}" in out                         # exemplo
    for name in STAGE_NAMES:
        assert name in out
    assert "etapas 3 e 4 da demo" in out and "etapas 8 e 9 da demo" in out


def test_cli_help_as_separate_process_exits_0():
    proc = _python("-m", "src.cli.main", "--help", timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "demo" in proc.stdout and "auditar" in proc.stdout


def test_demo_help_is_the_demos_own_help_and_cites_the_six_stages(capsys):
    assert cli.main(["demo", "--help"]) == 0
    out = capsys.readouterr().out
    assert f"usage: {CLI_PROG} demo" in out
    assert "--pause" in out and "--output-dir" in out
    for name in STAGE_NAMES:
        assert name in out
    assert "64 = erro de uso" in out


def test_demo_and_auditor_help_still_exit_0_directly(capsys):
    assert demo.main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "--output-dir" in out and "--pause" in out
    assert auditor_mod.main(["--help"]) == 0
    assert "usage: python -m src.auditor.auditor" in capsys.readouterr().out


def test_auditar_help_exits_0(capsys):
    assert cli.main(["auditar", "--help"]) == 0
    out = capsys.readouterr().out
    assert f"usage: {CLI_PROG} auditar" in out and "--json" in out


def test_spec_stage_mapping_matches_the_demo_steps():
    assert demo.SPEC_STAGES == EXPECTED_SPEC_STAGES
    assert cli.SPEC_STAGES == demo.SPEC_STAGES  # cópia na CLI (sem importar demo no --help)
    covered = [n for _, numbers in demo.SPEC_STAGES for n in numbers]
    assert covered == [number for number, *_ in demo.STEPS] == list(range(1, demo.TOTAL_STEPS + 1))
    titles = {number: title for number, title, *_ in demo.STEPS}
    assert titles[1] == "Configuração da eleição"
    assert titles[2] == "Autoridades e eleitores"
    assert titles[5] == "Encerramento da votação"
    assert all(titles[n].startswith("Apuração") for n in (6, 7))
    assert all(titles[n].startswith("Auditoria") for n in (8, 9))


# =============================================================================
# Não duplicação (AST) e imports tardios
# =============================================================================
FORBIDDEN_PACKAGES = ("src.crypto", "src.bulletin_board", "src.authorities", "src.server",
                      "src.election")
ALLOWED_PROJECT_MODULES = {"demo", "src.auditor.auditor"}
STDLIB = set(getattr(sys, "stdlib_module_names", ())) | {"__future__"}


def _resolve_relative(package: str, level: int, module: str | None) -> str | None:
    parts = package.split(".")
    if level - 1 >= len(parts):
        return None  # sobe além de src: inválido
    base = parts[: len(parts) - (level - 1)]
    return ".".join(base + ([module] if module else []))


def import_violations(source: str, package: str = "src.cli", filename: str = "<texto>") -> list:
    """Motivos de recusa dos imports de ``source`` (lista vazia = ok)."""
    violations = []

    def check(name: str, lineno: int):
        if any(name == f or name.startswith(f + ".") for f in FORBIDDEN_PACKAGES):
            violations.append(f"{filename}:{lineno}: importa {name} (proibido na CLI)")
        elif name.split(".")[0] in STDLIB:
            return
        elif name not in ALLOWED_PROJECT_MODULES:
            violations.append(f"{filename}:{lineno}: importa {name} (só stdlib, demo e "
                              "src.auditor.auditor)")

    for node in ast.walk(ast.parse(source, filename=filename)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                check(alias.name, node.lineno)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = _resolve_relative(package, node.level, node.module)
                if base is None:
                    violations.append(f"{filename}:{node.lineno}: import relativo fora de src")
                    continue
            else:
                base = node.module
            if base.split(".")[0] in STDLIB:
                continue
            for alias in node.names:
                # "from src.auditor import auditor" importa src.auditor.auditor;
                # "from src.auditor.auditor import main" importa src.auditor.auditor.
                target = base if base in ALLOWED_PROJECT_MODULES else f"{base}.{alias.name}"
                check(target, node.lineno)
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name in {"__import__", "import_module"}:
                violations.append(f"{filename}:{node.lineno}: import dinâmico ({name})")
    return violations


def test_cli_imports_only_stdlib_demo_and_auditor():
    files = sorted(CLI_DIR.glob("*.py"))
    assert {f.name for f in files} >= {"__init__.py", "main.py"}
    problems = []
    for path in files:
        problems += import_violations(path.read_text(encoding="utf-8"), filename=path.name)
    assert problems == []


@pytest.mark.parametrize("source", [
    "import src.crypto",
    "import src.crypto.elgamal as e",
    "from src.bulletin_board.board import BulletinBoard",
    "from src import server",
    "from src.election import election",
    "from ..authorities import authority",
    "from .. import crypto",
    "from ...x import y",
    "import cryptography",
    "from src.auditor import board_tally",
    "import importlib\nimportlib.import_module('src.crypto')",
    "__import__('src.server')",
], ids=["import", "import-as", "from", "from-src", "from-pacote", "relativo-2",
        "relativo-pacote", "relativo-fora", "terceiros", "outro-modulo-do-auditor",
        "import_module", "__import__"])
def test_import_checker_catches_violations(source):
    assert import_violations(source) != []


@pytest.mark.parametrize("source", [
    "import sys\nfrom collections.abc import Callable\nfrom __future__ import annotations",
    "import demo",
    "from src.auditor import auditor",
    "from src.auditor.auditor import main",
    "import src.auditor.auditor",
])
def test_import_checker_accepts_allowed_imports(source):
    assert import_violations(source) == []


LOADED_PROBE = (
    "import contextlib, io, sys\n"
    "import src.cli.main as cli\n"
    "with contextlib.redirect_stdout(io.StringIO()):\n"
    "    rc = cli.main(sys.argv[1:])\n"
    "watch = ('demo', 'src.auditor', 'src.crypto', 'src.bulletin_board', 'src.server',\n"
    "         'src.election', 'src.authorities', 'cryptography')\n"
    "print(rc, sorted({m.split('.')[0] if m.startswith('cryptography') else '.'.join(m.split('.')[:2])\n"
    "                  for m in sys.modules if m.startswith(watch)}))\n"
)


def test_help_imports_neither_demo_nor_auditor():
    proc = _python("-c", LOADED_PROBE, "--help", timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "0 []"


def test_auditar_imports_only_the_auditor_side():
    proc = _python("-c", LOADED_PROBE, "auditar", "--help", timeout=60)
    assert proc.returncode == 0, proc.stderr
    rc, loaded = proc.stdout.strip().split(" ", 1)
    assert rc == "0"
    assert "demo" not in loaded and "src.server" not in loaded
    assert "src.election" not in loaded and "src.authorities" not in loaded
    assert "src.auditor" in loaded


def test_auditar_and_help_work_without_fcntl():
    # Simula o Windows nativo: ``import fcntl`` falha.
    for args in (["--help"], ["auditar", "--help"]):
        proc = _python("-c", RUN_CLI_WITHOUT_FCNTL, *args, timeout=60)
        assert proc.returncode == 0, proc.stderr
    proc = _python("-c", RUN_CLI_WITHOUT_FCNTL, "demo", "--output-dir", "x", timeout=60)
    assert proc.returncode == 3, proc.stderr
    assert "fcntl" in proc.stderr and "Traceback" not in proc.stderr


# =============================================================================
# Ponta a ponta (fcntl: Linux, macOS ou WSL)
# =============================================================================
@pytest.fixture(scope="module")
def demo_run(tmp_path_factory):
    pytest.importorskip("fcntl", reason=NO_FCNTL)
    output = tmp_path_factory.mktemp("cli_demo") / "saida"
    proc = _python("-m", "src.cli.main", "demo", "--output-dir", str(output), timeout=240)
    # Caminhos que a demo realmente gera (run_demo: <saída>/public e <saída>/tampered_public).
    return SimpleNamespace(proc=proc, output=output, public=output / "public",
                           tampered=output / "tampered_public")


def test_e2e_demo_via_cli_runs_the_nine_steps(demo_run):
    proc = demo_run.proc
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr
    for number in range(1, 10):
        assert f"[{number}/9]" in proc.stdout
    assert "RESULTADO: DEMONSTRAÇÃO OK" in proc.stdout
    assert re.search(r"Totais: Alice 2, Bob 1\b", proc.stdout)
    assert "Traceback" not in proc.stderr
    assert demo_run.public.is_dir() and demo_run.tampered.is_dir()
    assert not demo_run.output.resolve().is_relative_to(ROOT)


def test_e2e_auditar_valid_data_exits_0(demo_run):
    assert demo_run.proc.returncode == 0
    proc = _python("-m", "src.cli.main", "auditar", str(demo_run.public), timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ELEIÇÃO VÁLIDA" in proc.stdout

    proc = _python("-m", "src.cli.main", "auditar", str(demo_run.public), "--json", timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["valid"] is True


def test_e2e_auditar_tampered_copy_exits_1(demo_run):
    assert demo_run.proc.returncode == 0
    proc = _python("-m", "src.cli.main", "auditar", str(demo_run.tampered), timeout=120)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "ELEIÇÃO INVÁLIDA" in proc.stdout


def test_e2e_auditar_does_not_need_fcntl(demo_run):
    # Os dados vieram da demo (com fcntl); a auditoria roda sem ele (Windows nativo).
    assert demo_run.proc.returncode == 0
    valid = _python("-c", RUN_CLI_WITHOUT_FCNTL, "auditar", str(demo_run.public), timeout=120)
    tampered = _python("-c", RUN_CLI_WITHOUT_FCNTL, "auditar", str(demo_run.tampered), timeout=120)
    assert (valid.returncode, tampered.returncode) == (0, 1), valid.stderr + tampered.stderr
