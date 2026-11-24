"""Interface de linha de comando da URNA_ONLINE (enxuta).

Uso::

    python -m src.cli.main demo [--pause] [--output-dir DIR]
    python -m src.cli.main auditar [DIR_PUBLICO] [--json]
    python -m src.cli.main --help

A especificação pede uma eleição com pelo menos 2 candidatos cobrindo
configuração, cadastro de eleitores, votação, encerramento, apuração e
auditoria, e aceita uma interface de linha de comando. A demonstração
(``demo.py``) percorre as seis etapas com os módulos reais; esta CLI apenas
reutiliza os dois pontos de entrada que já existem:

- ``demo``    -> ``demo.main(argv)``
- ``auditar`` -> ``src.auditor.auditor.main(argv)``

Regras (conferidas em ``tests/cli/test_cli.py``):

- A CLI só escolhe o subcomando. O RESTO da linha de comando é repassado sem
  ser interpretado (``--pause``, ``--output-dir``, ``--json`` e o diretório
  são opções dos pontos de entrada, não daqui), e o código de saída recebido
  é devolvido sem alteração.
- Não duplica lógica: importa só a biblioteca padrão, ``demo`` e
  ``src.auditor.auditor``; nunca ``src.crypto``, ``src.bulletin_board``,
  ``src.authorities``, ``src.server`` ou ``src.election``.
- Imports tardios: cada subcomando importa o seu módulo só ao ser executado.
  ``--help`` não importa nenhum dos dois, e ``auditar`` não depende de
  ``fcntl`` (funciona no Windows nativo); ``demo`` exige Linux, macOS ou WSL
  e sai com 3 no Windows nativo.
- Erro de uso (sem subcomando, subcomando ou opção desconhecidos) sai com 64
  (``EX_USAGE``), o mesmo código que ``demo.py`` e o auditor usam para opção
  inválida; assim nenhum código fica ambíguo (2 é "diretório recusado" na demo
  e "erro de configuração" no auditor).
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence

PROG = "python -m src.cli.main"

# Erro de uso: EX_USAGE de sysexits.h (o mesmo de demo.EXIT_USAGE e do auditor).
EXIT_OK = 0
EXIT_USAGE = 64

# Etapas da especificação -> etapas da demo. Cópia de demo.SPEC_STAGES (a CLI
# não importa demo só para mostrar a ajuda); um teste garante que são iguais.
SPEC_STAGES = (
    ("configuração", (1,)),
    ("cadastro de eleitores", (2,)),
    ("votação", (3, 4)),
    ("encerramento", (5,)),
    ("apuração", (6, 7)),
    ("auditoria", (8, 9)),
)


def _run_demo(argv: list[str]) -> int:
    import demo  # tardio: carrega os módulos do projeto só quando a demo roda

    return demo.main(argv, prog=f"{PROG} demo")


def _run_auditar(argv: list[str]) -> int:
    from src.auditor import auditor  # tardio; não depende de fcntl

    return auditor.main(argv, prog=f"{PROG} auditar")


# nome -> (função, descrição de uma linha, exemplo)
COMMANDS: dict[str, tuple[Callable[[list[str]], int], str, str]] = {
    "demo": (
        _run_demo,
        "demonstração em 9 etapas que cobre as seis etapas abaixo (demo.py)",
        f"{PROG} demo --pause",
    ),
    "auditar": (
        _run_auditar,
        "auditor independente sobre um diretório público (src.auditor.auditor)",
        f"{PROG} auditar data/demo/public",
    ),
}

HELP_FLAGS = ("-h", "--help")


def _steps(numbers: tuple[int, ...]) -> str:
    label = "etapa" if len(numbers) == 1 else "etapas"
    return f"{label} {' e '.join(str(n) for n in numbers)}"


def usage() -> str:
    return f"uso: {PROG} [-h] {{{','.join(COMMANDS)}}} [argumentos do subcomando ...]"


def help_text() -> str:
    lines = [
        usage(),
        "",
        "Interface de linha de comando da URNA_ONLINE. Só escolhe o subcomando e repassa",
        "o resto dos argumentos, sem interpretá-los, ao ponto de entrada existente; o",
        "código de saída é o do subcomando.",
        "",
        "subcomandos:",
    ]
    width = max(len(name) for name in COMMANDS)
    for name, (_, description, example) in COMMANDS.items():
        lines.append(f"  {name:<{width}}  {description}")
        lines.append(f"  {'':<{width}}  ex.: {example}")
    lines += ["", "etapas da especificação cobertas pela demo:"]
    width = max(len(stage) for stage, _ in SPEC_STAGES)
    for stage, numbers in SPEC_STAGES:
        extra = " (e o subcomando auditar)" if stage == "auditoria" else ""
        lines.append(f"  {stage:<{width}}  {_steps(numbers)} da demo{extra}")
    lines += [
        "",
        f'opções de cada subcomando: "{PROG} <subcomando> --help".',
        "códigos de saída: os do subcomando; 64 = erro de uso da CLI.",
    ]
    return "\n".join(lines)


def _print(text: str, stream) -> None:
    # Console Windows sem UTF-8: troca o que não couber em vez de quebrar.
    try:
        print(text, file=stream)
    except UnicodeEncodeError:
        encoding = getattr(stream, "encoding", None) or "ascii"
        print(text.encode(encoding, "replace").decode(encoding), file=stream)


def _usage_error(message: str) -> int:
    _print(usage(), sys.stderr)
    _print(f"{PROG}: erro: {message}", sys.stderr)
    return EXIT_USAGE


def main(argv: Sequence[str] | None = None) -> int:
    """Escolhe o subcomando e devolve o código de saída do ponto de entrada."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        _print(help_text(), sys.stderr)
        _print(f"\n{PROG}: erro: informe um subcomando ({', '.join(COMMANDS)})", sys.stderr)
        return EXIT_USAGE
    command, rest = args[0], args[1:]
    if command in HELP_FLAGS:
        _print(help_text(), sys.stdout)
        return EXIT_OK
    if command.startswith("-"):
        return _usage_error(f"opção desconhecida antes do subcomando: {command!r}")
    if command not in COMMANDS:
        return _usage_error(
            f"subcomando desconhecido: {command!r} (escolha entre {', '.join(COMMANDS)})"
        )
    run = COMMANDS[command][0]
    return run(rest)  # código do ponto de entrada, sem alteração


if __name__ == "__main__":
    sys.exit(main())
