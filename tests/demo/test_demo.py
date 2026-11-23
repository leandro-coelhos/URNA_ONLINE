"""Testes do roteiro automatizado da demonstração (Issue T15, ``demo.py``).

Tudo é verificado pelo relatório estruturado (``DemoReport``/``StepReport``)
devolvido por ``run_demo`` e pelos arquivos gerados, não pelo texto do stdout.
O roteiro roda os módulos reais (sem mocks) em ``tmp_path``; nada é escrito
em ``data/`` do repositório.

As execuções completas usam o ``BulletinBoard`` real, que exige ``fcntl``
(Linux, macOS ou WSL): no Windows nativo elas são puladas com o motivo, e o
teste da mensagem de "plataforma sem fcntl" continua rodando.

Limite de tempo
---------------
Medido neste ambiente: ~10,5 s por execução completa (p de 2048 bits com
teste de primalidade, RSA-3072 para 3 eleitores e o servidor, 2 auditorias).
O limite de 60 s (o do enunciado) deixa margem de ~6x para máquinas mais
lentas e para a variação da geração de chaves RSA, e continua bem abaixo do
tempo da apresentação; o alvo do demo é < 30 s.
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import demo  # noqa: E402
from src.auditor.auditor import (  # noqa: E402
    CHECK_AGGREGATE,
    CHECK_HASH_CHAIN,
    CHECK_RESULT,
    CHECK_SIGNATURES,
    Auditor,
)

TIME_LIMIT_S = 60.0
NO_FCNTL = "src.bulletin_board.board usa fcntl: o quadro público real exige Linux, macOS ou WSL"
SKIPPED_DIRS = {".git", ".pytest_cache", "__pycache__", ".venv"}


def _repo_snapshot() -> dict:
    """Todos os arquivos do projeto (fora caches) com tamanho e mtime."""
    snapshot = {}
    for path in ROOT.rglob("*"):
        if any(part in SKIPPED_DIRS for part in path.relative_to(ROOT).parts):
            continue
        if path.is_file():
            stat = path.stat()
            snapshot[path.relative_to(ROOT).as_posix()] = (stat.st_size, stat.st_mtime_ns)
    return snapshot


def _board(path: Path) -> list:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


@pytest.fixture(scope="module")
def demo_run(tmp_path_factory):
    pytest.importorskip("fcntl", reason=NO_FCNTL)
    parent = tmp_path_factory.mktemp("demo")
    output = parent / "saida"
    before = _repo_snapshot()
    report = demo.run_demo(output)  # sem pausa
    return SimpleNamespace(report=report, output=output, parent=parent,
                           repo_before=before, repo_after=_repo_snapshot())


# =============================================================================
# Sucesso geral e as 9 etapas
# =============================================================================
def test_demo_succeeds_with_the_nine_steps_in_order(demo_run):
    report = demo_run.report
    assert report.success, [(s.number, s.error) for s in report.steps if not s.ok]
    assert [s.number for s in report.steps] == list(range(1, 10))
    assert [s.title for s in report.steps] == [title for _, title, *_ in demo.STEPS]
    for step in report.steps:
        assert step.ok and step.error is None, (step.number, step.error)
        assert step.checks and all(ok for _, ok in step.checks), (step.number, step.failed_checks)
        assert step.concept and step.expected and step.obtained


def test_each_step_obtained_the_expected_result(demo_run):
    report = demo_run.report
    step1, step2, step3 = report.step(1), report.step(2), report.step(3)
    assert step1.data["p_bits"] >= 2048 and step1.data["candidates"] == list(demo.CANDIDATES)

    # Etapa 2: h = h_1·h_2·h_3 mod p, recalculado aqui.
    product = 1
    for h_i in step2.data["authority_h"].values():
        product = product * h_i % demo.GROUP.p
    assert len(step2.data["authority_h"]) == 3
    assert step2.data["joint_public_key"] == product
    assert step2.data["voters"] == [v for v, _ in demo.VOTE_PLAN]

    # Etapa 3: 3 recibos distintos e 3 registros no quadro.
    assert step3.data["board_size"] == 3
    assert len(set(step3.data["receipts"].values())) == 3
    assert len(set(step3.data["record_hashes"].values())) == 3

    assert report.step(4).data["error_type"] == "DuplicateVoteError"
    assert report.step(5).data["state"] == "ENCERRADA"
    assert report.step(5).data["late_error_type"] == "VotingClosedError"
    step6 = report.step(6).data
    assert step6["error_type"] == "MissingAuthorityShareError"
    assert step6["absent"] == demo.ABSENT_AUTHORITY and "'3'" in step6["error"]
    # Etapa 7: antes da apuração, o agregado forjado (só a cédula do
    # eleitor-1) é recusado pela autoridade, que confere o quadro.
    step7 = report.step(7)
    assert step7.data["attack_error_type"] == "AggregateVerificationError"
    assert "ballot_count informado 1, esperado 3" in step7.data["attack_error"]
    assert ("autoridade recusa o agregado forjado com AggregateVerificationError", True) in step7.checks
    assert report.step(8).data["valid"] is True and report.step(8).data["state"] == "AUDITADA"
    assert report.step(9).data["valid"] is False


def test_step7_shows_the_forged_aggregate_being_refused(demo_run):
    """A nova linha da etapa 7: ataque ao sigilo e a recusa da autoridade."""
    step7 = demo_run.report.step(7)
    attack = (f"servidor malicioso envia à autoridade {demo.ATTACKED_AUTHORITY} só a cédula de "
              f"{demo.TARGET_VOTER} como agregado (ballot_count 1)")
    assert step7.details[0] == attack
    assert step7.details[1].startswith("recusa: AggregateVerificationError: agregado recusado")
    text = demo.format_step(step7)
    assert f"    · {attack}" in text
    assert "    · recusa: AggregateVerificationError: " in text
    # A recusa vem antes das parcelas válidas, e a apuração segue normalmente.
    assert step7.details[2].startswith(f"autoridade {demo.AUTHORITY_IDS[0]}: d(Alice)")
    assert step7.data["totals"] == {"Alice": 2, "Bob": 1}


def test_totals_match_the_fixed_vote_plan(demo_run):
    expected = dict(Counter(choice for _, choice in demo.VOTE_PLAN))
    assert expected == {"Alice": 2, "Bob": 1}  # A, B, A
    assert demo.EXPECTED_TOTALS == expected
    assert demo_run.report.totals == expected
    assert demo_run.report.step(7).data["totals"] == expected
    result = json.loads((demo_run.report.public_dir / "result.json").read_text())
    assert result["totals"] == expected


# =============================================================================
# Auditor: aprova os dados válidos, reprova a cópia adulterada
# =============================================================================
def test_auditor_approves_valid_data_and_rejects_tampered_copy(demo_run):
    report = demo_run.report
    assert report.step(8).data["failed_checks"] == []
    failed = report.step(9).data["failed_checks"]
    assert {CHECK_HASH_CHAIN, CHECK_SIGNATURES} <= set(failed)
    where = f"entrada {demo.TAMPER_ENTRY}"
    assert any(e.startswith(where) and "alterado" in e for e in failed[CHECK_HASH_CHAIN])
    assert any(e.startswith(where) and "assinatura" in e for e in failed[CHECK_SIGNATURES])

    # Reauditoria independente dos diretórios gerados.
    assert Auditor(report.public_dir).run().valid
    again = Auditor(report.tampered_dir).run()
    assert not again.valid
    assert {c.name for c in again.failures} == {CHECK_HASH_CHAIN, CHECK_SIGNATURES,
                                                CHECK_AGGREGATE, CHECK_RESULT}


def test_tampering_happens_only_in_the_copy(demo_run):
    report = demo_run.report
    public, tampered = report.public_dir, report.tampered_dir
    assert sorted(p.name for p in public.iterdir()) == sorted(p.name for p in tampered.iterdir())
    for path in public.iterdir():
        if path.name != demo.BOARD_FILE:
            assert path.read_bytes() == (tampered / path.name).read_bytes(), path.name

    original, altered = _board(public / demo.BOARD_FILE), _board(tampered / demo.BOARD_FILE)
    assert len(original) == len(altered) == 3
    position = demo.CANDIDATES.index(demo.TAMPER_CANDIDATE)
    for index, (a, b) in enumerate(zip(original, altered)):
        if index != demo.TAMPER_ENTRY:
            assert a == b
            continue
        # Só c2 do candidato escolhido mudou: c2 · g (m -> m+1), sem refazer hash.
        c2 = int(a["ballot"]["ciphertexts"][position]["c2"])
        assert int(b["ballot"]["ciphertexts"][position]["c2"]) == c2 * demo.GROUP.g % demo.GROUP.p
        b["ballot"]["ciphertexts"][position]["c2"] = a["ballot"]["ciphertexts"][position]["c2"]
        assert a == b
    # O quadro válido continua sendo aceito pelo próprio BulletinBoard real.
    from src.bulletin_board.hash_chain import read_records, verify_board

    election = json.loads((public / "election.json").read_text())
    with open(public / demo.BOARD_FILE, "rb") as fh:
        records = list(read_records(fh))
    checkpoint = {"schema_version": 1, "election_id": demo.ELECTION_ID, "size": 3,
                  "head_hash": records[-1]["hash"]}
    verify_board(records, election_id=demo.ELECTION_ID, candidate_ids=demo.CANDIDATES,
                 voter_public_keys={v["voter_id"]: v["public_key_pem"] for v in election["voters"]},
                 expected_checkpoint=checkpoint)


def test_public_and_private_are_separated(demo_run):
    report = demo_run.report
    assert sorted(p.name for p in report.private_dir.iterdir()) == [
        "authority_1.key", "authority_2.key", "authority_3.key"
    ]
    xs = [str(json.loads(p.read_text())["x"]) for p in report.private_dir.iterdir()]
    for directory in (report.public_dir, report.tampered_dir):
        for path in directory.iterdir():
            text = path.read_text(encoding="utf-8")
            assert "PRIVATE KEY" not in text and '"x"' not in text, path
            assert not any(x in text for x in xs), path
    assert sorted(p.name for p in report.output_dir.iterdir()) == [
        demo.MARKER_FILE, "private", "public", "tampered_public"
    ]


# =============================================================================
# Isolamento e tempo
# =============================================================================
def test_nothing_is_written_outside_the_output_dir(demo_run):
    assert demo_run.repo_after == demo_run.repo_before, "o demo escreveu no repositório"
    assert sorted(p.name for p in demo_run.parent.iterdir()) == [demo_run.output.name]
    assert demo_run.report.output_dir == demo_run.output.resolve()


def test_full_run_fits_the_time_limit(demo_run):
    report = demo_run.report
    assert report.paused == 0
    assert report.elapsed < TIME_LIMIT_S, f"{report.elapsed:.1f} s"
    assert sum(step.elapsed for step in report.steps) <= report.elapsed


# =============================================================================
# Segunda execução (CLI com --pause): recria tudo e chega aos mesmos totais
# =============================================================================
def test_second_run_via_cli_recreates_data_with_same_totals(demo_run, monkeypatch, capsys):
    output = demo_run.output
    old_joint_key = json.loads((output / "public" / "election.json").read_text())["joint_public_key"]
    (output / "public" / "lixo.txt").write_text("de uma execução anterior")
    prompts = []
    monkeypatch.setattr("builtins.input", lambda prompt="": prompts.append(prompt) or "")

    assert demo.main(["--output-dir", str(output), "--pause"]) == demo.EXIT_OK

    out = capsys.readouterr().out
    assert len(prompts) == demo.TOTAL_STEPS - 1  # Enter entre as etapas
    assert not (output / "public" / "lixo.txt").exists()  # diretório recriado
    new = json.loads((output / "public" / "election.json").read_text())
    result = json.loads((output / "public" / "result.json").read_text())
    assert result["totals"] == demo.EXPECTED_TOTALS  # mesmos totais...
    assert new["joint_public_key"] != old_joint_key   # ...com aleatoriedade nova
    assert "DEMONSTRAÇÃO OK" in out
    for number in range(1, 10):
        assert f"[{number}/9]" in out
    # Saída legível: nenhum número de 2048 bits ou hash completo impresso.
    assert not re.search(r"[0-9a-f]{40,}", out)
    assert not re.search(r"\d{40,}", out)


# =============================================================================
# Divergências e erros: código de saída diferente de 0
# =============================================================================
def test_divergence_stops_the_demo_and_exits_nonzero(tmp_path, monkeypatch, capsys):
    pytest.importorskip("fcntl", reason=NO_FCNTL)
    # Simula um resultado errado: os totais esperados não batem com o voto.
    monkeypatch.setattr(demo, "EXPECTED_TOTALS", {"Alice": 1, "Bob": 2})
    captured = {}
    real_run = demo.run_demo

    def spy(*args, **kwargs):
        captured["report"] = real_run(*args, **kwargs)
        return captured["report"]

    monkeypatch.setattr(demo, "run_demo", spy)
    code = demo.main(["--output-dir", str(tmp_path / "saida")])

    report = captured["report"]
    assert code == demo.EXIT_DIVERGED
    assert not report.success
    assert [s.number for s in report.steps] == list(range(1, 8))  # parou na 7
    assert not report.step(7).ok
    assert "totais iguais à distribuição definida" in report.step(7).failed_checks
    err = capsys.readouterr().err
    assert "etapa 7 divergiu" in err


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, EOFError], ids=["ctrl-c", "ctrl-d"])
def test_interrupt_at_pause_prompt_exits_130_without_traceback(tmp_path, monkeypatch, capsys,
                                                               interrupt):
    pytest.importorskip("fcntl", reason=NO_FCNTL)
    prompts = []

    def interrupted_input(prompt=""):
        prompts.append(prompt)
        raise interrupt  # Ctrl+C (KeyboardInterrupt) ou Ctrl+D (EOFError) no prompt

    monkeypatch.setattr("builtins.input", interrupted_input)
    code = demo.main(["--output-dir", str(tmp_path / "saida"), "--pause"])

    assert code == demo.EXIT_INTERRUPTED == 130
    assert code not in (demo.EXIT_OK, demo.EXIT_DIVERGED, demo.EXIT_BAD_OUTPUT_DIR,
                        demo.EXIT_NO_FCNTL)
    out, err = capsys.readouterr()
    assert len(prompts) == 1  # parou na primeira pausa, depois da etapa 1
    assert "[1/9]" in out and "[2/9]" not in out and "DEMONSTRAÇÃO OK" not in out
    assert "Demonstração interrompida pelo usuário" in err
    assert "Traceback" not in out + err


def test_authority_without_aggregate_check_makes_step7_diverge(tmp_path, monkeypatch, capsys):
    """Se a autoridade NÃO recusasse o agregado forjado, a demo acusaria (saída 1).

    Simula a autoridade de antes desta mudança: a conferência com o quadro é
    trocada por uma que aceita tudo. A cédula do eleitor-1 seria decifrada,
    então a etapa 7 diverge e a demo para nela.
    """
    pytest.importorskip("fcntl", reason=NO_FCNTL)
    from src.authorities import partial_decryption

    monkeypatch.setattr(partial_decryption, "_verify_aggregate_against_board",
                        lambda *args, **kwargs: None)
    captured = {}
    real_run = demo.run_demo

    def spy(*args, **kwargs):
        captured["report"] = real_run(*args, **kwargs)
        return captured["report"]

    monkeypatch.setattr(demo, "run_demo", spy)
    code = demo.main(["--output-dir", str(tmp_path / "saida")])

    report = captured["report"]
    assert code == demo.EXIT_DIVERGED
    assert [s.number for s in report.steps] == list(range(1, 8))  # parou na 7
    assert not report.step(7).ok
    assert report.step(7).data["attack_error_type"] is None
    assert ("autoridade recusa o agregado forjado com AggregateVerificationError"
            in report.step(7).failed_checks)
    assert "etapa 7 divergiu" in capsys.readouterr().err


def test_ctrl_c_during_a_step_also_exits_130(tmp_path, monkeypatch, capsys):
    # Ctrl+C no meio de uma etapa (com ou sem --pause) cai no mesmo tratamento.
    monkeypatch.setattr(demo, "fcntl_available", lambda: True)

    def interrupted_run(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(demo, "run_demo", interrupted_run)
    assert demo.main(["--output-dir", str(tmp_path / "saida")]) == demo.EXIT_INTERRUPTED
    err = capsys.readouterr().err
    assert "Demonstração interrompida pelo usuário" in err and "Traceback" not in err


def test_missing_fcntl_exits_with_clear_message_and_creates_nothing(tmp_path, monkeypatch, capsys):
    # Roda em qualquer sistema: simula a ausência de fcntl (Windows nativo).
    monkeypatch.setattr(demo, "fcntl_available", lambda: False)
    output = tmp_path / "saida"

    assert demo.main(["--output-dir", str(output)]) == demo.EXIT_NO_FCNTL
    err = capsys.readouterr().err
    assert "fcntl" in err and "WSL" in err and "Traceback" not in err
    with pytest.raises(demo.DemoPlatformError, match="fcntl"):
        demo.run_demo(output)
    assert not output.exists()


@pytest.mark.parametrize("target", [
    ROOT / "data" / "public",
    ROOT / "data" / "private",
    ROOT / "data" / "public" / "sub",
    ROOT,
], ids=["data-public", "data-private", "dentro-de-public", "raiz"])
def test_output_dir_never_touches_real_data_or_project(target):
    before = _repo_snapshot()
    with pytest.raises(ValueError):
        demo.prepare_output_dir(target)
    assert _repo_snapshot() == before


def test_foreign_non_empty_dir_is_not_deleted(tmp_path, monkeypatch, capsys):
    foreign = tmp_path / "alheio"
    foreign.mkdir()
    (foreign / "importante.txt").write_text("não apagar")
    with pytest.raises(ValueError, match=demo.MARKER_FILE):
        demo.prepare_output_dir(foreign)
    monkeypatch.setattr(demo, "fcntl_available", lambda: True)
    monkeypatch.setattr(demo, "_load_board_modules", lambda: SimpleNamespace())
    assert demo.main(["--output-dir", str(foreign)]) == demo.EXIT_BAD_OUTPUT_DIR
    assert (foreign / "importante.txt").read_text() == "não apagar"
    assert "ERRO" in capsys.readouterr().err


def test_default_output_dir_is_data_demo_and_ignored_by_git():
    assert demo.DEFAULT_OUTPUT_DIR == ROOT / "data" / "demo"
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "data/demo/" in ignored
