"""Testes do auditor independente (Item 4, ``src/auditor/auditor.py``).

Cenário
-------
Uma eleição completa é montada UMA vez por sessão SÓ com os módulos reais do
repositório: ``Registration`` (cadastro), ``Election``/``VotingService``
(votação), ``src.bulletin_board.board.BulletinBoard`` (quadro público),
``src.crypto`` (cifras, envelopes e assinaturas), ``Authority`` (chaves em
``data/private/``) e ``partial_decryption`` (agregado, parcelas, provas e
``result.json``). São 3 eleitores, 3 autoridades e 2 candidatos; o resultado
esperado é Alice 2 x 1 Bob. Nenhum módulo é substituído em ``sys.modules``.

O cenário e os auxiliares (leitura/adulteração do quadro, auditoria) ficam em
``tests/support/election_scenario.py``; os fixtures ``rsa_keys``,
``scenario`` e ``public_copy`` ficam em ``tests/conftest.py``. Assim a suíte
de segurança (T14) reutiliza a mesma eleição.

Cada teste copia SOMENTE ``data/public/`` para um diretório novo, adultera a
cópia e roda o auditor sobre ela. O auditor nunca vê ``data/private/``.
"""

import ast
import builtins
import copy
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip(
    "fcntl",
    reason="src.bulletin_board.board usa fcntl: o quadro público real exige Linux, macOS ou WSL",
)

from tests.support.election_scenario import (
    CANDIDATES,
    ELECTION_ID,
    EXPECTED_TOTALS,
    N_AUTHORITIES,
    ROOT,
    VOTES,
    G,
    P,
    _chain,
    _forged_entry,
    _public_pem,
    audit,
    ballot_with_bit_proofs,
    board_voters,
    build_election,
    errors_of,
    failed,
    read_board,
    read_json,
    signed_ballot,
    write_board,
    write_json,
)

from src.auditor.auditor import (  # noqa: E402
    CHECK_AGGREGATE,
    CHECK_ELIGIBILITY,
    CHECK_HASH_CHAIN,
    CHECK_NAMES,
    CHECK_PUBLIC_DATA,
    CHECK_RESULT,
    CHECK_SIGNATURES,
    Auditor,
    audit_election,
    main,
)
from src.bulletin_board.hash_chain import BoardFormatError  # noqa: E402
from src.crypto.ballots import BallotFormatError  # noqa: E402

auditor_mod = sys.modules["src.auditor.auditor"]

_NO_PROOF_FIELD = (
    "O envelope de src.crypto.ballots (e o registro do quadro) não tem campo para a "
    "prova 0/1: sign_ballot recusa a cédula com prova (BallotFormatError). Quando "
    "src.crypto.bit_proof entrar no formato, este teste passa a executar e o xfail "
    "estrito obriga a atualizá-lo."
)


# =============================================================================
# Sanidade do cenário
# =============================================================================
def test_scenario_is_a_complete_valid_election(scenario):
    assert scenario.election_state == "APURACAO"
    assert scenario.result["totals"] == EXPECTED_TOTALS
    election = read_json(scenario.public_dir, "election.json")
    assert len(election["voters"]) == 3 and len(election["authorities"]) == 3
    assert election["candidates"] == CANDIDATES
    assert board_voters(read_board(scenario.public_dir)) == list(VOTES)
    # O quadro é o real: o próprio BulletinBoard relê e verifica o arquivo.
    assert [r["hash"] for r in scenario.board.records()] == [
        e["hash"] for e in read_board(scenario.public_dir)
    ]
    # Chaves privadas só em data/private/; nada privado em data/public/.
    assert sorted(p.name for p in scenario.private_dir.iterdir()) == [
        f"authority_{i}.key" for i in range(1, N_AUTHORITIES + 1)
    ]
    for path in scenario.public_dir.iterdir():
        assert "PRIVATE KEY" not in path.read_text(encoding="utf-8")
        assert '"x"' not in path.read_text(encoding="utf-8")


# =============================================================================
# Item 4 — caso base: eleição válida
# =============================================================================
def test_valid_election_passes_audit(public_copy):
    report = audit(public_copy)

    assert report.valid, report.format()
    assert report.election_id == ELECTION_ID
    assert [check.name for check in report.checks] == list(CHECK_NAMES)
    assert all(check.passed and check.errors == () for check in report.checks)
    assert report.errors == ()
    text = report.format()
    assert "ELEIÇÃO VÁLIDA" in text and "FALHA" not in text


def test_audit_election_shortcut_and_report_dict(public_copy):
    report = audit_election(public_copy)
    data = report.to_dict()
    assert data["valid"] is True and data["election_id"] == ELECTION_ID
    assert [c["name"] for c in data["checks"]] == list(CHECK_NAMES)
    json.dumps(data)  # serializável


def test_auditor_reads_only_public_files(public_copy, scenario, monkeypatch):
    opened = []
    real_open = builtins.open

    def tracking_open(file, *args, **kwargs):
        opened.append(Path(file).resolve())
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", tracking_open)
    report = audit(public_copy)
    monkeypatch.undo()

    assert report.valid, report.format()
    assert opened, "o auditor deveria ler os arquivos públicos"
    root = public_copy.resolve()
    assert all(path.parent == root for path in opened), opened
    assert {p.name for p in opened} <= {
        "election.json", "voters.json", "bulletin_board.jsonl",
        "aggregate_ciphertexts.json", "authority_partials.json", "result.json",
    }
    assert not any("private" in part for path in opened for part in path.parts)


def test_auditor_imports_only_crypto_and_bulletin_board():
    """O auditor só pode importar ``src.crypto`` e ``src.bulletin_board``.

    Nada de ``src.server`` (estado do servidor), ``src.election`` nem
    ``src.authorities`` (código de quem é auditado).
    """
    allowed = ("src.crypto", "src.bulletin_board")
    for source in (ROOT / "src" / "auditor").glob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            elif isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            else:
                continue
            for name in names:
                if name == "src" or name.startswith("src."):
                    assert name.startswith(allowed), f"{source.name} importa {name}"
        # Nenhum literal de caminho para a pasta privada (docstrings a citam
        # entre ``crases``, não entre aspas).
        text = source.read_text(encoding="utf-8")
        assert '"data/private' not in text and "'data/private" not in text
        assert ".key" not in text


def test_auditor_proof_check_matches_partial_decryption_protocol(scenario):
    """O auditor refaz a verificação de Chaum-Pedersen sem importar as autoridades.

    Este teste (que pode importar ambos) garante que os dois lados usam o
    mesmo protocolo público: mesmo domínio e mesmo desafio Fiat-Shamir.
    """
    from src.authorities import partial_decryption as pd

    assert auditor_mod.PROOF_DOMAIN == pd.PROOF_DOMAIN
    election_data = read_json(scenario.public_dir, "election.json")
    aggregate = read_json(scenario.public_dir, "aggregate_ciphertexts.json")
    partials = read_json(scenario.public_dir, "authority_partials.json")["partials"]
    pd_ctx = pd._parse_election(election_data)
    auditor = Auditor(scenario.public_dir)
    audit_ctx = auditor._load_public_context([])
    for submission in partials:
        authority_id = submission["authority_id"]
        h_i = pd_ctx.authorities[authority_id]
        for cid, share in submission["shares"].items():
            args = (authority_id, cid, h_i, int(aggregate["ciphertexts"][cid]["c1"]),
                    int(share["d"]), int(share["a1"]), int(share["a2"]))
            assert auditor._challenge(audit_ctx, *args) == pd._challenge(pd_ctx, *args)


# =============================================================================
# Item 4 — adulteração de uma cédula no quadro público
# =============================================================================
@pytest.mark.security
def test_tampered_ballot_detected_by_chain_and_signature(public_copy):
    entries = read_board(public_copy)
    # Multiplicar c2 por g troca o voto cifrado (m -> m+1) sem conhecer r.
    target = entries[1]["ballot"]["ciphertexts"][0]
    target["c2"] = str(int(target["c2"]) * G % P)
    write_board(public_copy, entries)

    report = audit(public_copy)

    assert not report.valid
    assert {CHECK_HASH_CHAIN, CHECK_SIGNATURES} <= failed(report)
    chain = report.check(CHECK_HASH_CHAIN).errors
    assert len(chain) == 1 and chain[0].startswith("entrada 1:") and "alterado" in chain[0]
    signatures = report.check(CHECK_SIGNATURES).errors
    assert len(signatures) == 1 and signatures[0].startswith("entrada 1:")
    assert "assinatura" in signatures[0]
    # O agregado publicado e o resultado também deixam de conferir.
    assert {CHECK_AGGREGATE, CHECK_RESULT} <= failed(report)
    assert report.check(CHECK_ELIGIBILITY).passed
    assert "ELEIÇÃO INVÁLIDA" in report.format()


@pytest.mark.security
def test_tampered_ballot_with_recomputed_chain_still_caught_by_signature(public_copy):
    # Atacante mais cuidadoso: refaz todos os hashes depois de alterar a cifra.
    entries = read_board(public_copy)
    target = entries[0]["ballot"]["ciphertexts"][1]
    target["c1"] = str(int(target["c1"]) * G % P)
    write_board(public_copy, _chain(entries))

    report = audit(public_copy)

    assert report.check(CHECK_HASH_CHAIN).passed
    assert CHECK_SIGNATURES in failed(report)
    assert errors_of(report, CHECK_SIGNATURES).startswith("entrada 0:")
    assert not report.valid


def test_extra_field_in_board_record_detected(public_copy):
    """Antes: "recibo adulterado no quadro". O registro real NÃO publica recibo.

    O recibo agora é derivado da cédula assinada (``compute_receipt``), então
    não há campo de recibo para adulterar. O ataque equivalente (enfiar um
    campo extra, como um "recibo", num registro) é recusado pelo formato do
    quadro: nem o atacante consegue refazer a cadeia, e o auditor acusa a
    entrada.
    """
    entries = read_board(public_copy)
    entries[2]["receipt"] = "0" * 64
    with pytest.raises(BoardFormatError):
        _chain(entries)  # hash_record não aceita campos extras
    write_board(public_copy, entries)

    report = audit(public_copy)

    assert failed(report) == {CHECK_HASH_CHAIN}
    assert "entrada 2: registro fora do formato público do quadro" in errors_of(report, CHECK_HASH_CHAIN)


# =============================================================================
# Cadeia de hashes: remoção e reordenação
# =============================================================================
@pytest.mark.security
def test_removed_entry_breaks_chain(public_copy):
    entries = read_board(public_copy)
    del entries[1]
    write_board(public_copy, entries)

    report = audit(public_copy)

    assert CHECK_HASH_CHAIN in failed(report)
    chain = errors_of(report, CHECK_HASH_CHAIN)
    assert "entrada 1: index 2 fora de ordem" in chain
    assert "entrada 1: previous_hash não corresponde" in chain
    # O voto removido também some do produto homomórfico.
    assert CHECK_AGGREGATE in failed(report)


@pytest.mark.security
def test_reordered_entries_break_chain(public_copy):
    entries = read_board(public_copy)
    entries[0], entries[1] = entries[1], entries[0]
    write_board(public_copy, entries)

    report = audit(public_copy)

    assert CHECK_HASH_CHAIN in failed(report)
    chain = errors_of(report, CHECK_HASH_CHAIN)
    assert "entrada 0: index 1 fora de ordem" in chain
    assert "entrada 1: index 0 fora de ordem" in chain
    assert "previous_hash" in chain
    # As cédulas em si continuam íntegras: só a ordem foi violada.
    assert report.check(CHECK_SIGNATURES).passed
    assert report.check(CHECK_AGGREGATE).passed  # o produto é comutativo


@pytest.mark.security
def test_removed_last_entry_is_caught_by_homomorphic_product(public_copy):
    # Limitação conhecida: tirar o ÚLTIMO registro não quebra nenhum elo.
    entries = read_board(public_copy)
    write_board(public_copy, entries[:-1])

    report = audit(public_copy)

    assert report.check(CHECK_HASH_CHAIN).passed
    assert CHECK_AGGREGATE in failed(report)
    assert "difere do produto recalculado" in errors_of(report, CHECK_AGGREGATE)
    assert not report.valid


def test_malformed_board_line_is_reported_without_crashing(public_copy):
    with open(public_copy / "bulletin_board.jsonl", "a", encoding="utf-8") as fh:
        fh.write("isto não é JSON\n")
    report = audit(public_copy)
    assert "linha 4: registro não é um objeto JSON" in errors_of(report, CHECK_HASH_CHAIN)
    assert CHECK_AGGREGATE in failed(report)
    assert not report.valid


# =============================================================================
# Elegibilidade e unicidade
# =============================================================================
@pytest.mark.security
def test_vote_from_unregistered_voter_detected(public_copy, scenario):
    entries = read_board(public_copy)
    # O intruso assina com a própria chave e o atacante refaz a cadeia.
    entries.append(_forged_entry("intruso", scenario.intruder_key, "Bob", scenario.joint_key))
    write_board(public_copy, _chain(entries))

    report = audit(public_copy)

    assert report.check(CHECK_HASH_CHAIN).passed  # cadeia sozinha não basta
    assert "entrada 3: eleitor 'intruso' não está cadastrado" in errors_of(report, CHECK_ELIGIBILITY)
    assert "entrada 3: eleitor 'intruso' sem chave cadastrada" in errors_of(report, CHECK_SIGNATURES)
    assert not report.valid


@pytest.mark.security
def test_duplicate_vote_detected(public_copy, scenario):
    entries = read_board(public_copy)
    # Segundo voto legítimo (assinado pelo próprio eleitor-1) inserido no quadro.
    entries.append(_forged_entry("eleitor-1", scenario.voter_keys["eleitor-1"], "Bob",
                                 scenario.joint_key))
    write_board(public_copy, _chain(entries))

    report = audit(public_copy)

    assert report.check(CHECK_HASH_CHAIN).passed
    assert report.check(CHECK_SIGNATURES).passed  # a assinatura é verdadeira
    assert "eleitor 'eleitor-1' votou 2 vezes (entradas [0, 3])" in errors_of(report, CHECK_ELIGIBILITY)
    assert not report.valid


def test_copied_ciphertext_detected(public_copy, scenario):
    # eleitor-2 reenvia, assinada por ele, a cifra do eleitor-1 (replica o voto).
    entries = read_board(public_copy)
    pairs = [(int(c["c1"]), int(c["c2"])) for c in entries[0]["ballot"]["ciphertexts"]]
    envelope = signed_ballot("eleitor-2", scenario.voter_keys["eleitor-2"], pairs)
    entries[1].update(ballot=envelope["ballot"], signature=envelope["signature"])
    write_board(public_copy, _chain(entries))

    report = audit(public_copy)
    assert "entrada 1: c1 da cifra 0 repete o da entrada 0" in errors_of(report, CHECK_SIGNATURES)


def test_voter_inserted_into_voters_json_detected(public_copy, scenario):
    voters = read_json(public_copy, "voters.json")
    voters["voters"].append({"voter_id": "intruso",
                             "public_key_pem": _public_pem(scenario.intruder_key)})
    write_json(public_copy, "voters.json", voters)

    report = audit(public_copy)

    assert "só em voters.json ['intruso']" in errors_of(report, CHECK_PUBLIC_DATA)
    # Sem cadastro confiável, nenhuma outra verificação é aceita.
    assert failed(report) == set(CHECK_NAMES)
    assert "não executada" in errors_of(report, CHECK_RESULT)


def test_voters_json_is_optional(public_copy):
    (public_copy / "voters.json").unlink()
    assert audit(public_copy).valid


# =============================================================================
# Agregação homomórfica e resultado
# =============================================================================
def test_aggregate_divergence_detected(public_copy):
    aggregate = read_json(public_copy, "aggregate_ciphertexts.json")
    c2 = int(aggregate["ciphertexts"]["Bob"]["c2"])
    aggregate["ciphertexts"]["Bob"]["c2"] = str(c2 * G % P)  # +1 voto para Bob
    write_json(public_copy, "aggregate_ciphertexts.json", aggregate)

    report = audit(public_copy)

    assert failed(report) == {CHECK_AGGREGATE}
    assert errors_of(report, CHECK_AGGREGATE) == (
        "aggregate_ciphertexts.json: C2 de 'Bob' difere do produto recalculado do quadro"
    )


@pytest.mark.security
@pytest.mark.parametrize(
    "totals",
    [{"Alice": 3, "Bob": 1}, {"Alice": 1, "Bob": 2}, {"Alice": 2, "Bob": 0}],
    ids=["alice+1", "trocados", "bob-zerado"],
)
def test_tampered_result_totals_detected(public_copy, totals):
    result = read_json(public_copy, "result.json")
    result["totals"] = totals
    write_json(public_copy, "result.json", result)

    report = audit(public_copy)

    assert failed(report) == {CHECK_RESULT}
    message = errors_of(report, CHECK_RESULT)
    for cid in CANDIDATES:
        mismatch = f"total publicado de {cid!r} ({totals[cid]}) não corresponde"
        assert (mismatch in message) == (totals[cid] != EXPECTED_TOTALS[cid])


@pytest.mark.security
def test_total_above_number_of_ballots_detected(public_copy):
    result = read_json(public_copy, "result.json")
    result["totals"]["Alice"] = 99
    write_json(public_copy, "result.json", result)
    assert "total de 'Alice' (99) fora de [0, 3]" in errors_of(audit(public_copy), CHECK_RESULT)


@pytest.mark.security
@pytest.mark.parametrize("totals", [{"Alice": 3, "Bob": 1}, {"Alice": 2, "Bob": 0}],
                         ids=["soma-4", "soma-2"])
def test_totals_sum_must_equal_number_of_ballots(public_copy, totals):
    """Σ totais = nº de cédulas do quadro (não há voto em branco).

    Detecção agregada: o motivo não aponta cédula nem eleitor.
    """
    result = read_json(public_copy, "result.json")
    result["totals"] = totals
    write_json(public_copy, "result.json", result)

    report = audit(public_copy)

    assert failed(report) == {CHECK_RESULT}
    message = errors_of(report, CHECK_RESULT)
    assert (f"soma dos totais ({sum(totals.values())}) difere do número de cédulas "
            "do quadro (3)") in message
    assert "detecção agregada" in message and "m = -1 e m = 2" in message
    assert not any(voter in message for voter in VOTES)


def test_totals_sum_is_checked_even_without_all_partials(public_copy):
    # A soma não depende das parcelas: aparece junto com a parcela faltante.
    partials = read_json(public_copy, "authority_partials.json")
    partials["partials"] = partials["partials"][:-1]
    write_json(public_copy, "authority_partials.json", partials)
    result = read_json(public_copy, "result.json")
    result["totals"] = {"Alice": 3, "Bob": 1}
    write_json(public_copy, "result.json", result)

    message = errors_of(audit(public_copy), CHECK_RESULT)
    assert "faltam parcelas das autoridades ['3']" in message
    assert "soma dos totais (4) difere do número de cédulas do quadro (3)" in message


@pytest.mark.security
def test_abstention_limit_is_number_of_ballots_not_voters(tmp_path, rsa_keys):
    """Abstenção: 3 eleitores cadastrados, 2 cédulas.

    Apuração e auditor usam o mesmo limite, o nº de cédulas (2), e a eleição
    honesta com abstenção é válida. Um total 3 (= nº de eleitores) é recusado.
    """
    sc = build_election(tmp_path, rsa_keys, votes={"eleitor-1": (1, 0), "eleitor-2": (0, 1)})
    election = read_json(sc.public_dir, "election.json")
    assert len(election["voters"]) == 3 and len(read_board(sc.public_dir)) == 2
    assert sc.result["totals"] == {"Alice": 1, "Bob": 1}
    assert sc.result["max_votes"] == 2  # antes: 3 (nº de eleitores)
    assert audit(sc.public_dir).valid

    result = read_json(sc.public_dir, "result.json")
    result["totals"]["Alice"] = 3
    write_json(sc.public_dir, "result.json", result)
    report = audit(sc.public_dir)
    assert failed(report) == {CHECK_RESULT}
    assert "total de 'Alice' (3) fora de [0, 2]" in errors_of(report, CHECK_RESULT)


@pytest.mark.security
def test_missing_authority_partial_detected(public_copy):
    partials = read_json(public_copy, "authority_partials.json")
    partials["partials"] = partials["partials"][:-1]
    write_json(public_copy, "authority_partials.json", partials)

    report = audit(public_copy)

    assert failed(report) == {CHECK_RESULT}
    assert "faltam parcelas das autoridades ['3']" in errors_of(report, CHECK_RESULT)


@pytest.mark.security
def test_tampered_authority_partial_detected(public_copy):
    partials = read_json(public_copy, "authority_partials.json")
    share = partials["partials"][0]["shares"]["Alice"]
    share["d"] = str(int(share["d"]) * G % P)
    write_json(public_copy, "authority_partials.json", partials)

    report = audit(public_copy)

    assert failed(report) == {CHECK_RESULT}
    assert "parcela rejeitada" in errors_of(report, CHECK_RESULT)


def test_tampered_joint_key_in_election_json_detected(public_copy):
    election = read_json(public_copy, "election.json")
    election["joint_public_key"] = str(int(election["joint_public_key"]) * G % P)
    write_json(public_copy, "election.json", election)
    report = audit(public_copy)
    assert "joint_public_key publicada difere" in errors_of(report, CHECK_PUBLIC_DATA)
    assert not report.valid


@pytest.mark.parametrize(
    "missing, check",
    [
        ("election.json", CHECK_PUBLIC_DATA),
        ("bulletin_board.jsonl", CHECK_HASH_CHAIN),
        ("aggregate_ciphertexts.json", CHECK_AGGREGATE),
        ("authority_partials.json", CHECK_RESULT),
        ("result.json", CHECK_RESULT),
    ],
)
def test_missing_public_file_is_a_failure(public_copy, missing, check):
    (public_copy / missing).unlink()
    report = audit(public_copy)
    assert not report.valid
    assert check in failed(report)
    assert missing in errors_of(report, check)


# =============================================================================
# Provas de validade 0/1
#
# O formato da cédula e do quadro não transporta a prova (limitação
# documentada; coerente com o cenário 7 da T14). O que é verificável hoje:
# uma cédula com prova não é aceita "em silêncio". O resto fica registrado
# como xfail estrito, com a prova REAL de src.crypto.bit_proof.
# =============================================================================
def test_proof_present_is_not_silently_accepted(public_copy, scenario):
    """Uma prova enfiada num registro não passa despercebida (nem é ignorada).

    Antes: "prova presente sem verificador". Hoje não há campo de prova: o
    registro com ``ballot.proof`` sai do formato do quadro e da cédula
    assinada, e o auditor acusa a entrada nas duas verificações.
    """
    from src.crypto.bit_proof import prove_bit
    from src.crypto.elgamal import encrypt_bit

    entries = read_board(public_copy)
    ciphertext, r = encrypt_bit(1, scenario.joint_key)
    proof = prove_bit(ciphertext, scenario.joint_key, r, 1)
    entries[0]["ballot"]["proof"] = {k: str(v) for k, v in vars(proof).items()}
    write_board(public_copy, entries)

    report = audit(public_copy)

    assert {CHECK_HASH_CHAIN, CHECK_SIGNATURES} <= failed(report)
    assert errors_of(report, CHECK_HASH_CHAIN).startswith("entrada 0: registro fora do formato")
    assert errors_of(report, CHECK_SIGNATURES).startswith("entrada 0: cédula fora do formato")


@pytest.mark.xfail(strict=True, raises=BallotFormatError, reason=_NO_PROOF_FIELD)
def test_ballots_with_valid_proofs_pass(scenario):
    envelope = ballot_with_bit_proofs("eleitor-1", scenario.voter_keys["eleitor-1"], (1, 0),
                                      scenario.joint_key)
    assert envelope["ballot"]["proof"]
    pytest.fail("atualize: o auditor precisa verificar as provas 0/1 de cada cédula")


@pytest.mark.xfail(strict=True, raises=BallotFormatError, reason=_NO_PROOF_FIELD)
def test_invalid_proof_detected(scenario):
    envelope = ballot_with_bit_proofs("eleitor-1", scenario.voter_keys["eleitor-1"], (1, 0),
                                      scenario.joint_key)
    assert envelope["ballot"]["proof"]
    pytest.fail("atualize: uma prova 0/1 inválida deve reprovar a entrada")


@pytest.mark.xfail(strict=True, raises=BallotFormatError, reason=_NO_PROOF_FIELD)
def test_required_proof_missing_detected(scenario):
    envelope = ballot_with_bit_proofs("eleitor-1", scenario.voter_keys["eleitor-1"], (1, 0),
                                      scenario.joint_key)
    assert envelope["ballot"]["proof"]
    pytest.fail("atualize: com prova obrigatória, cédulas sem prova devem reprovar")


@pytest.mark.xfail(strict=True, raises=TypeError, reason=_NO_PROOF_FIELD)
def test_require_proof_needs_verifier(public_copy):
    # Hoje o Auditor nem tem a opção require_proof (TypeError).
    with pytest.raises(ValueError):
        Auditor(public_copy, require_proof=True)


# =============================================================================
# Configuração e CLI
# =============================================================================
def test_signature_verification_is_mandatory(public_copy, monkeypatch):
    # Sem o verificador de src.crypto.ballots não existe auditoria "vazia".
    monkeypatch.setattr(auditor_mod, "verify_signed_ballot", None)
    with pytest.raises(RuntimeError, match="verify_signed_ballot"):
        Auditor(public_copy)


def test_failing_signature_verifier_counts_as_invalid(public_copy, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("verificador quebrado")

    monkeypatch.setattr(auditor_mod, "verify_signed_ballot", broken)
    report = audit(public_copy)
    assert failed(report) == {CHECK_SIGNATURES}
    assert errors_of(report, CHECK_SIGNATURES).count("não verificável") == len(VOTES)


def test_verifier_returning_other_ballot_counts_as_invalid(public_copy, monkeypatch):
    # O verificador precisa devolver EXATAMENTE a cédula do registro.
    monkeypatch.setattr(auditor_mod, "verify_signed_ballot", lambda *a, **k: {"outra": "cédula"})
    report = audit(public_copy)
    assert failed(report) == {CHECK_SIGNATURES}
    assert "verificação inconsistente" in errors_of(report, CHECK_SIGNATURES)


def test_cli_exit_codes(public_copy, monkeypatch, capsys):
    assert main([str(public_copy)]) == 0
    assert "ELEIÇÃO VÁLIDA" in capsys.readouterr().out

    assert main([str(public_copy), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True

    entries = read_board(public_copy)
    entries[0]["ballot"]["voter_id"] = "eleitor-2"
    write_board(public_copy, entries)
    assert main([str(public_copy)]) == 1
    out = capsys.readouterr().out
    assert "ELEIÇÃO INVÁLIDA" in out and "[FALHA]" in out

    monkeypatch.setattr(auditor_mod, "verify_signed_ballot", None)
    assert main([str(public_copy)]) == 2
    assert "verify_signed_ballot" in capsys.readouterr().err


def test_board_file_is_untouched_by_audit(public_copy):
    before = (public_copy / "bulletin_board.jsonl").read_bytes()
    original = copy.deepcopy(read_board(public_copy))
    audit(public_copy)
    assert (public_copy / "bulletin_board.jsonl").read_bytes() == before
    assert read_board(public_copy) == original
