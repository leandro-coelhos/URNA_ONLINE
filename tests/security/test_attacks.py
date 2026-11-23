"""Testes de segurança e adulteração (Issue T14, #13).

Cada ataque exigido pelo enunciado tem pelo menos um teste reproduzível. Este
arquivo contém só os cenários que AINDA NÃO estavam cobertos; os já cobertos
por outros arquivos estão marcados com ``@pytest.mark.security`` no próprio
arquivo e listados na tabela de rastreabilidade do README. Assim
``python -m pytest -q -m security`` roda a suíte T14 inteira.

Todos os dados ficam em diretórios temporários do pytest. A eleição vem de
``tests/support/election_scenario.py`` (o mesmo cenário do auditor), SÓ com
os módulos reais de ``src/``: envelopes e assinaturas de ``src.crypto``,
quadro ``src.bulletin_board.board.BulletinBoard`` e apuração de
``src.authorities.partial_decryption``. Nada é substituído em ``sys.modules``.

Observações sobre esta árvore (ver o README, "Desvantagens e limitações")
-------------------------------------------------------------------------
- Não existe cliente do eleitor em ``src/``: o eleitor honesto usa
  ``encrypt_bit`` + ``sign_ballot``; o malicioso cifra ``m`` fora de {0, 1}
  com ``pow`` (``encrypt_bit`` recusaria) e assina um envelope válido.
- Não há prova de conhecimento zero de que cada cifra é 0 ou 1 no formato da
  cédula: ``src.crypto.bit_proof`` existe, mas o envelope não tem campo para
  ela. Os testes do cenário 7 documentam o que é e o que não é detectável.
"""

import base64
import dataclasses
import secrets
import shutil

import pytest

pytest.importorskip(
    "fcntl",
    reason="src.bulletin_board.board usa fcntl: o quadro público real exige Linux, macOS ou WSL",
)

from tests.support.election_scenario import (
    BOARD_FILE,
    CANDIDATES,
    GROUP,
    N_AUTHORITIES,
    ROOT,
    VOTES,
    G,
    P,
    Q,
    audit,
    board_ciphertexts,
    build_election,
    encrypted_ballot,
    errors_of,
    failed,
    publish_tally,
    read_board,
    read_json,
    write_board,
    write_json,
    signed_ballot,
    _chain,
    _encrypt,
)

from src.auditor.auditor import (  # noqa: E402
    CHECK_AGGREGATE,
    CHECK_ELIGIBILITY,
    CHECK_HASH_CHAIN,
    CHECK_RESULT,
    CHECK_SIGNATURES,
)
from src.authorities import partial_decryption as pd_mod  # noqa: E402
from src.authorities.partial_decryption import (  # noqa: E402
    AggregateVerificationError,
    AuthorityPartialSubmission,
    DecryptionError,
    InconsistentTotalsError,
    InvalidShareError,
    MissingAuthorityShareError,
    PartialDecryptionCollector,
    TallyStateError,
    build_aggregate,
    combine_and_decrypt_result,
    compute_authority_partials,
    load_public_json,
)
from src.election.election import InvalidProofError, InvalidSignatureError, compute_receipt  # noqa: E402
from src.election.states import InvalidStateTransitionError  # noqa: E402

pytestmark = pytest.mark.security

TALLY_FILES = ("aggregate_ciphertexts.json", "authority_partials.json", "result.json")


# =============================================================================
# Guarda: nenhum teste toca em data/ do repositório
# =============================================================================
def _repo_data_snapshot():
    data_dir = ROOT / "data"
    if not data_dir.exists():
        return None
    return sorted((str(p.relative_to(data_dir)), p.stat().st_mtime_ns)
                  for p in data_dir.rglob("*"))


@pytest.fixture(autouse=True)
def _repo_data_untouched():
    before = _repo_data_snapshot()
    yield
    assert _repo_data_snapshot() == before, "um teste escreveu em data/ do repositório"


# =============================================================================
# Auxiliares
# =============================================================================
def _public_side_effects(sc) -> tuple:
    """Tudo o que uma cédula aceita alteraria: quadro, cédulas persistidas e memória."""
    return (
        (sc.public_dir / "bulletin_board.jsonl").read_bytes(),
        (sc.public_dir / "accepted_ballots.json").read_bytes(),
        sc.election.accepted_ballots,
        sc.service.pending_publications,
    )


def _aggregate_data(ballots) -> dict:
    """Produto homomórfico em memória (build_aggregate real, sem gravar arquivo)."""
    return build_aggregate("eleicao-2026", CANDIDATES, ballots, GROUP)


def _bypassed_partials(authorities, election_data, aggregate_data) -> list:
    """Parcelas com provas válidas de autoridades que PULARAM as conferências.

    Simula uma autoridade comprometida (ou um servidor que tenha obtido as
    parcelas de outro modo): usa o cálculo interno ``_prove_share``, sem a
    etapa e sem a conferência do agregado com o quadro. Serve para mostrar
    que o lado do servidor também recusa, de forma independente.
    """
    ctx = pd_mod._parse_election(election_data)
    aggregate = pd_mod._parse_aggregate(aggregate_data, ctx)
    return [
        AuthorityPartialSubmission(authority.authority_id, tuple(
            pd_mod._prove_share(authority, ctx, cid, aggregate[cid][0], authority.public_key().h)
            for cid in sorted(aggregate)
        ))
        for authority in authorities
    ]


def _combine(election_data, aggregate_data, submissions, result_path, **kwargs):
    # inverse_mod e bounded_discrete_log reais (padrões de combine_and_decrypt_result).
    kwargs.setdefault("election_state", "APURACAO")
    return combine_and_decrypt_result(
        election_data, aggregate_data, submissions,
        result_path=result_path, **kwargs,
    )


@pytest.fixture
def open_election(tmp_path, rsa_keys):
    """Votação aberta, com a cédula do eleitor-2 já publicada no quadro."""
    sc = build_election(tmp_path, rsa_keys, votes={"eleitor-2": (0, 1)}, until="VOTACAO_ABERTA")
    assert len(read_board(sc.public_dir)) == 1
    return sc


# =============================================================================
# Cenário 3 — assinatura inválida, rejeitada pelo servidor sem efeito colateral
# (3a, chave de outro eleitor, já está em test_election_voting.py e
# test_server_voting.py; ver o README)
# =============================================================================
def _flip_signature_byte(envelope: dict) -> None:
    raw = bytearray(base64.b64decode(envelope["signature"]))
    raw[len(raw) // 2] ^= 0x01  # um bit no meio da assinatura RSA
    envelope["signature"] = base64.b64encode(bytes(raw)).decode("ascii")


def _alter_after_signing(envelope: dict) -> None:
    # c2 · g troca m por m+1 sem conhecer r; a cifra continua no subgrupo.
    target = envelope["ballot"]["ciphertexts"][0]
    target["c2"] = str(int(target["c2"]) * G % P)


@pytest.mark.parametrize(
    "tamper",
    [_flip_signature_byte, _alter_after_signing],
    ids=["3b-bytes-da-assinatura-alterados", "3c-cedula-alterada-apos-assinar"],
)
def test_invalid_signature_rejected_without_side_effects(open_election, tamper):
    sc = open_election
    ballot = encrypted_ballot("eleitor-1", sc.voter_keys["eleitor-1"], (1, 0), sc.joint_key)
    tamper(ballot)
    before = _public_side_effects(sc)

    with pytest.raises(InvalidSignatureError, match="assinatura inválida"):
        sc.service.receive_ballot(ballot)

    # Nenhum recibo (a chamada lançou), quadro e cédulas persistidas intactos.
    assert _public_side_effects(sc) == before
    assert len(read_board(sc.public_dir)) == 1
    assert not sc.election.has_voted("eleitor-1")


# =============================================================================
# Cenário 4c — remoção da ÚLTIMA entrada do quadro
# (alteração, remoção intermediária e reordenação: tests/auditor/test_auditor.py)
# =============================================================================
def test_removed_last_entry_after_tally_is_detected_but_not_located(public_copy):
    """Remover a última entrada não quebra nenhum elo da cadeia de hashes.

    A remoção é detectada por OUTRO meio: o produto homomórfico recalculado
    diverge de ``aggregate_ciphertexts.json`` e as parcelas das autoridades
    (provas feitas sobre o agregado original) deixam de conferir. O relatório
    diz QUAIS verificações falharam, mas não consegue apontar o índice nem o
    eleitor removido: os arquivos públicos não guardam o tamanho do quadro.
    """
    entries = read_board(public_copy)
    removed = entries[-1]
    write_board(public_copy, entries[:-1])

    report = audit(public_copy)

    assert not report.valid
    assert failed(report) == {CHECK_AGGREGATE, CHECK_RESULT}
    assert report.check(CHECK_HASH_CHAIN).passed
    aggregate = errors_of(report, CHECK_AGGREGATE)
    for cid in CANDIDATES:
        assert f"C1 de {cid!r} difere do produto recalculado do quadro" in aggregate
        assert f"C2 de {cid!r} difere do produto recalculado do quadro" in aggregate
    assert "parcela rejeitada" in errors_of(report, CHECK_RESULT)
    # Limitação documentada: nada no relatório identifica a entrada removida.
    every_error = "\n".join(report.errors)
    assert removed["ballot"]["voter_id"] not in every_error
    assert f"entrada {removed['index']}" not in every_error


def test_removed_last_entry_before_tally_is_not_detectable_by_auditor(scenario, tmp_path):
    """LIMITAÇÃO CONHECIDA, documentada com o comportamento atual.

    Um administrador que remove a última cédula do quadro ANTES da apuração e
    apura o quadro truncado produz arquivos públicos coerentes entre si:
    cadeia íntegra, agregado = produto do quadro, parcelas válidas e
    resultado conferido. Para o auditor, isso é indistinguível de o eleitor
    ter se abstido. Só a verificação individual (o eleitor procura o próprio
    recibo no quadro) revela a remoção.
    """
    public_dir = tmp_path / "publico"
    shutil.copytree(scenario.public_dir, public_dir)
    for name in TALLY_FILES:
        (public_dir / name).unlink()

    entries = read_board(public_dir)[:-1]
    write_board(public_dir, entries)
    # O mesmo administrador também trunca a cópia persistida pelo servidor
    # (o auditor nem a lê, mas assim nenhum arquivo público contradiz o quadro).
    accepted = read_json(public_dir, "accepted_ballots.json")
    accepted["ballots"] = accepted["ballots"][:-1]
    write_json(public_dir, "accepted_ballots.json", accepted)

    result = publish_tally(public_dir, scenario.authorities, board_ciphertexts(entries),
                           election_state="APURACAO")

    assert result["totals"] == {"Alice": 1, "Bob": 1}  # o voto do eleitor-3 sumiu
    report = audit(public_dir)
    assert report.valid, report.format()  # comportamento atual: não detectado

    # Verificação individual: o recibo do eleitor-3 não está no quadro. O
    # quadro real não publica recibos: cada um é recalculado da cédula
    # assinada do registro (compute_receipt), como o eleitor faria.
    on_board = {compute_receipt(entry["ballot"], entry["signature"]) for entry in entries}
    assert scenario.receipts["eleitor-1"].receipt in on_board
    assert scenario.receipts["eleitor-3"].receipt not in on_board


# =============================================================================
# Cenário 5 — resultado antes do encerramento
# (voto após o encerramento e transições para trás: test_election_voting.py e
# test_server_voting.py; ver o README)
# =============================================================================
@pytest.mark.parametrize("stage", ["CONFIGURACAO", "CADASTRO", "VOTACAO_ABERTA"])
def test_tally_before_closing_is_rejected_and_publishes_nothing(tmp_path, rsa_keys, stage):
    sc = build_election(tmp_path, rsa_keys, until="CADASTRO" if stage == "CONFIGURACAO" else stage)
    election_data = load_public_json(sc.public_dir / "election.json")

    if stage == "CONFIGURACAO":
        # Nenhum objeto Election fica em CONFIGURACAO: o construtor É essa
        # etapa e já devolve a eleição em CADASTRO. A etapa é informada à
        # apuração por um provedor, como faria o servidor.
        state = lambda: "CONFIGURACAO"  # noqa: E731
        ballots = [[_encrypt(0, sc.joint_key) for _ in CANDIDATES]]  # agregado forjado
    else:
        state = sc.election.current_state
        assert state() == stage
        with pytest.raises(InvalidStateTransitionError, match=f"transição {stage} -> APURACAO"):
            sc.election.start_tally()
        assert sc.election.current_state() == stage
        if stage == "VOTACAO_ABERTA":
            # Ataque à justiça: apurar as cédulas já aceitas = resultado parcial.
            assert len(sc.election.accepted_ballots) == len(VOTES)
            ballots = [record.ciphertexts for record in sc.election.accepted_ballots]
        else:
            ballots = [[_encrypt(0, sc.joint_key) for _ in CANDIDATES]]
    aggregate_data = _aggregate_data(ballots)
    board_path = sc.public_dir / "bulletin_board.jsonl"

    # Lado das autoridades: nenhuma calcula parcela fora de APURACAO (a etapa
    # é conferida antes do quadro).
    for authority in sc.authorities:
        with pytest.raises(TallyStateError, match=f"etapa atual: {stage}"):
            compute_authority_partials(authority, election_data, aggregate_data,
                                       board_path=board_path, election_state=state)
    # Lado do servidor: nem o coletor nem a combinação aceitam a etapa,
    # mesmo recebendo parcelas obtidas sem informar a etapa às autoridades.
    with pytest.raises(TallyStateError, match=f"etapa atual: {stage}"):
        PartialDecryptionCollector(election_data, aggregate_data,
                                   election_state=state)
    if stage == "VOTACAO_ABERTA":
        # O agregado parcial é o produto do quadro atual: sem a etapa, a
        # autoridade calcula (só a etapa impede o resultado parcial).
        smuggled = [compute_authority_partials(a, election_data, aggregate_data,
                                               board_path=board_path)
                    for a in sc.authorities]
    else:
        # Agregado forjado com o quadro ainda vazio: mesmo sem saber a etapa,
        # a autoridade honesta recusa decifrar.
        for authority in sc.authorities:
            with pytest.raises(AggregateVerificationError, match="quadro público vazio"):
                compute_authority_partials(authority, election_data, aggregate_data,
                                           board_path=board_path)
        smuggled = _bypassed_partials(sc.authorities, election_data, aggregate_data)
    with pytest.raises(TallyStateError, match=f"etapa atual: {stage}"):
        _combine(election_data, aggregate_data, smuggled, sc.public_dir / "result.json",
                 election_state=state)

    for name in TALLY_FILES:
        assert not (sc.public_dir / name).exists(), name


# =============================================================================
# Cenário 6 — apuração sem uma das autoridades
# =============================================================================
@pytest.fixture(scope="module")
def tally_inputs(scenario):
    """Dados públicos da eleição completa e as parcelas válidas das 3 autoridades."""
    election_data = load_public_json(scenario.public_dir / "election.json")
    aggregate_data = load_public_json(scenario.public_dir / "aggregate_ciphertexts.json")
    partials = [
        compute_authority_partials(a, election_data, aggregate_data,
                                   board_path=scenario.public_dir / "bulletin_board.jsonl",
                                   election_state="APURACAO")
        for a in scenario.authorities
    ]
    assert [s.authority_id for s in partials] == [str(i) for i in range(1, N_AUTHORITIES + 1)]
    return election_data, aggregate_data, partials


@pytest.mark.parametrize("missing", ["1", "2", "3"])
def test_tally_without_one_authority_fails(tally_inputs, tmp_path, missing):
    election_data, aggregate_data, partials = tally_inputs
    present = [s for s in partials if s.authority_id != missing]
    assert len(present) == 2
    result_path = tmp_path / "result.json"

    with pytest.raises(MissingAuthorityShareError,
                       match=rf"faltam parcelas das autoridades \['{missing}'\]"):
        _combine(election_data, aggregate_data, present, result_path)

    assert not result_path.exists()


def _tampered_d(partials):
    first = partials[0]
    shares = tuple(
        dataclasses.replace(share, d=share.d * G % P) if share.candidate_id == "Alice" else share
        for share in first.shares
    )
    return [AuthorityPartialSubmission(first.authority_id, shares), *partials[1:]]


def _wrong_authority(partials):
    # A autoridade 2 envia também no lugar da 1, com as próprias parcelas.
    return [AuthorityPartialSubmission("1", partials[1].shares), *partials[1:]]


@pytest.mark.parametrize("forge", [_tampered_d, _wrong_authority],
                         ids=["parcela-adulterada", "autoridade-errada"])
def test_tally_with_forged_partial_publishes_no_result(tally_inputs, tmp_path, forge):
    election_data, aggregate_data, partials = tally_inputs
    result_path = tmp_path / "result.json"

    with pytest.raises(InvalidShareError, match=r"prova de '1'/'Alice' inválida"):
        _combine(election_data, aggregate_data, forge(partials), result_path)

    assert not result_path.exists()


# =============================================================================
# Cenário 7 — cifra de valor diferente de 0 ou 1
#
# O formato da cédula NÃO tem prova de conhecimento zero (ZKP) de que cada
# cifra é 0 ou 1: src.crypto.bit_proof existe, mas o envelope de
# src.crypto.ballots não tem campo para ela. Não existe cliente do eleitor em
# src/ para recusar m fora de {0, 1}; o eleitor malicioso abaixo cifra direto
# com pow e assina (sign_ballot real) uma cédula estruturalmente válida.
#
# Mitigação PARCIAL: apuração e auditor exigem que a soma dos totais seja
# IGUAL ao número de cédulas (não há voto em branco: cada cédula honesta
# cifra exatamente um 1). A detecção é AGREGADA: sabe-se que alguma cédula
# não soma 1, mas não qual nem de que eleitor. Cédulas que somam 1 com m fora
# de {0, 1}, como (-1, +2), continuam indetectáveis sem a prova 0/1.
# =============================================================================
INFLATED_VOTES = {"eleitor-1": (2, 0), "eleitor-2": (0, 1), "eleitor-3": (1, 0)}
# 1 para os dois candidatos: cada cifra é 0/1, mas a cédula vota duas vezes.
DOUBLE_VOTES = {"eleitor-1": (1, 1), "eleitor-2": (0, 1), "eleitor-3": (1, 0)}
# (-1, +2): a cédula ainda "soma 1", como uma honesta; tira um voto de Alice
# e dá dois a Bob.
COMPENSATED_VOTES = {"eleitor-1": (-1, 2), "eleitor-2": (1, 0), "eleitor-3": (0, 1)}


def _refused_then_forced(sc, totals: dict) -> Exception:
    """A apuração recusa o resultado; um servidor desonesto o publica mesmo assim.

    ``publish_tally`` grava agregado e parcelas (provas válidas) e para em
    ``combine_and_decrypt_result``, sem ``result.json``. Depois, o "servidor"
    escreve à mão os totais que a decifração conjunta realmente produz: todos
    conferem com ``C2 ≡ g^T · Π d_i``, então só a soma pode denunciá-los.
    """
    with pytest.raises(InconsistentTotalsError) as info:
        publish_tally(sc.public_dir, sc.authorities,
                      [record.ciphertexts for record in sc.election.accepted_ballots],
                      election_state=sc.election.current_state)
    assert not (sc.public_dir / "result.json").exists()
    write_json(sc.public_dir, "result.json", {
        "schema_version": 1, "election_id": "eleicao-2026", "totals": totals,
        "authorities": [str(i) for i in range(1, N_AUTHORITIES + 1)], "max_votes": len(VOTES),
    })
    return info.value


@pytest.fixture(scope="module")
def inflated(tmp_path_factory, rsa_keys):
    sc = build_election(tmp_path_factory.mktemp("m-igual-2"), rsa_keys,
                        votes=INFLATED_VOTES, tally=False)
    sc.tally_error = _refused_then_forced(sc, {"Alice": 3, "Bob": 1})
    return sc


@pytest.fixture(scope="module")
def double_vote(tmp_path_factory, rsa_keys):
    sc = build_election(tmp_path_factory.mktemp("um-para-os-dois"), rsa_keys,
                        votes=DOUBLE_VOTES, tally=False)
    sc.tally_error = _refused_then_forced(sc, {"Alice": 2, "Bob": 2})
    return sc


@pytest.fixture(scope="module")
def compensated(tmp_path_factory, rsa_keys):
    return build_election(tmp_path_factory.mktemp("m-menos-1-mais-2"), rsa_keys,
                          votes=COMPENSATED_VOTES)


@pytest.mark.parametrize(
    "fixture_name, totals",
    [("inflated", {"Alice": 3, "Bob": 1}), ("double_vote", {"Alice": 2, "Bob": 2})],
    ids=["m=2", "1-para-os-dois"],
)
def test_ballot_not_summing_one_is_detected_by_tally_and_auditor(request, fixture_name, totals):
    """Antes: aceito e auditado como válido (ex.: Alice 2 x 2 Bob para 3 cédulas).

    Agora, com cada total dentro de [0, 3], a SOMA (4) denuncia a cédula:
    a apuração não publica e, se o servidor publicar mesmo assim, o auditor
    reprova com motivo explícito. Detecção agregada: nem a apuração nem o
    auditor dizem qual cédula ou eleitor foi.
    """
    sc = request.getfixturevalue(fixture_name)
    assert sum(totals.values()) == len(VOTES) + 1
    assert all(0 <= t <= len(VOTES) for t in totals.values())

    # Servidor: sem prova 0/1, continua aceitando a cédula e emitindo recibo.
    assert set(sc.receipts) == set(VOTES)
    assert [e["ballot"]["voter_id"] for e in read_board(sc.public_dir)] == list(VOTES)

    # Apuração: recusou publicar.
    assert "soma dos totais (4) difere do número de cédulas (3)" in str(sc.tally_error)
    assert "detecção agregada" in str(sc.tally_error)

    # Auditor: reprova só tally_result, pela soma; cada total confere sozinho.
    report = audit(sc.public_dir)
    assert not report.valid
    assert failed(report) == {CHECK_RESULT}
    message = errors_of(report, CHECK_RESULT)
    assert "soma dos totais (4) difere do número de cédulas do quadro (3)" in message
    assert "não corresponde à decifração conjunta" not in message
    assert not any(voter in message for voter in VOTES)  # não aponta o eleitor


def test_ballot_keeping_sum_one_is_accepted_and_audits_valid(compensated):
    """LIMITAÇÃO CONHECIDA (README, "Desvantagens e limitações"), comportamento atual.

    (-1, +2) soma 1, como uma cédula honesta: cada total cai em [0, 3] e a
    soma é 3 = número de cédulas. A cédula é aceita, a apuração publica Alice
    0 x 3 Bob e o auditor considera a eleição válida. A verificação da soma
    é agregada e não pega isso; só a prova 0/1 por cifra pegaria.
    """
    sc = compensated
    assert set(sc.receipts) == set(VOTES)
    assert [e["ballot"]["voter_id"] for e in read_board(sc.public_dir)] == list(VOTES)
    assert sc.result["totals"] == {"Alice": 0, "Bob": 3}
    assert sum(sc.result["totals"].values()) == len(VOTES)
    report = audit(sc.public_dir)
    assert report.valid, report.format()


def test_abstention_bounds_totals_by_ballots_not_voters(tmp_path, rsa_keys):
    """Abstenção: 3 eleitores cadastrados, 1 cédula, que cifra m = 3 para Alice.

    Antes, a apuração limitava os totais a [0, nº de eleitores] = [0, 3] e
    publicava Alice 3, enquanto o auditor exigia [0, nº de cédulas] = [0, 1].
    Agora as duas usam o nº de cédulas.
    """
    sc = build_election(tmp_path, rsa_keys, votes={"eleitor-1": (3, 0)}, tally=False)
    with pytest.raises(DecryptionError, match=r"total de 'Alice' fora de \[0, 1\]"):
        publish_tally(sc.public_dir, sc.authorities,
                      [record.ciphertexts for record in sc.election.accepted_ballots],
                      election_state=sc.election.current_state)
    assert not (sc.public_dir / "result.json").exists()


@pytest.mark.parametrize(
    "votes",
    [
        {"eleitor-1": (1000, 0), "eleitor-2": (0, 1), "eleitor-3": (1, 0)},
        {"eleitor-1": (-1, 0), "eleitor-2": (0, 1), "eleitor-3": (0, 1)},
    ],
    ids=["m=1000", "m=-1-total-negativo"],
)
def test_non_binary_vote_out_of_bounds_blocks_the_tally(tmp_path, rsa_keys, votes):
    """Consequência detectável: o logaritmo discreto limitado não acha o total.

    Alice totaliza 1001 ou -1, fora de [0, 3]: a apuração falha com erro
    explícito e nada é publicado em ``result.json``. A detecção não aponta o
    eleitor culpado e impede a apuração inteira (negação de serviço).
    """
    sc = build_election(tmp_path, rsa_keys, votes=votes, tally=False)
    assert set(sc.receipts) == set(VOTES)  # o servidor aceitou a cédula maliciosa

    with pytest.raises(DecryptionError, match=r"total de 'Alice' fora de \[0, 3\]"):
        publish_tally(sc.public_dir, sc.authorities,
                      [record.ciphertexts for record in sc.election.accepted_ballots],
                      election_state=sc.election.current_state)

    assert not (sc.public_dir / "result.json").exists()
    report = audit(sc.public_dir)
    assert failed(report) == {CHECK_RESULT}
    assert "result.json não encontrado" in errors_of(report, CHECK_RESULT)
    for check in (CHECK_HASH_CHAIN, CHECK_ELIGIBILITY, CHECK_SIGNATURES, CHECK_AGGREGATE):
        assert report.check(check).passed


_NO_ZKP = (
    "Sem prova de conhecimento zero de que cada cifra é 0 ou 1 (README, "
    "'Desvantagens e limitações'): o servidor aceita a cédula e o auditor não "
    "a detecta. Quando houver ZKP, este teste passa e o xfail estrito obriga a "
    "atualizá-lo."
)


@pytest.mark.xfail(strict=True, raises=pytest.fail.Exception, reason=_NO_ZKP)
@pytest.mark.parametrize("m", [2, -1, 1000])
def test_server_should_reject_vote_outside_0_1(tmp_path, rsa_keys, m):
    sc = build_election(tmp_path, rsa_keys, votes={}, until="VOTACAO_ABERTA")
    ballot = encrypted_ballot("eleitor-1", sc.voter_keys["eleitor-1"], (m, 0), sc.joint_key)
    with pytest.raises(InvalidProofError):
        sc.service.receive_ballot(ballot)


# [m=2] era xfail(strict=True) e passou a ser satisfeito pela verificação da
# soma dos totais (4 votos para 3 cédulas): virou teste normal. A detecção é
# agregada, não identifica o eleitor. [m=-1-e-m=2] soma 1 e continua xfail.
@pytest.mark.parametrize(
    "fixture_name",
    [
        pytest.param("inflated", id="m=2"),
        pytest.param("compensated", id="m=-1-e-m=2",
                     marks=pytest.mark.xfail(strict=True, raises=AssertionError, reason=_NO_ZKP)),
    ],
)
def test_auditor_should_detect_vote_outside_0_1(request, fixture_name):
    report = audit(request.getfixturevalue(fixture_name).public_dir)
    assert not report.valid


# =============================================================================
# Cenário 8 — servidor malicioso tenta descobrir um voto pela decifração conjunta
# =============================================================================
# d_i = C1^(x_i) remove a parte de h^R de QUALQUER cifra. Se o servidor envia às
# autoridades a cifra de uma única cédula como se fosse o agregado, as parcelas
# a decifram (0 ou 1) e o voto daquele eleitor vaza, inclusive sem nada ser
# publicado. Por isso cada autoridade lê o quadro (board_path), verifica a
# cadeia e as assinaturas, recalcula o produto e o nº de cédulas e só então
# decifra. Toda recusa é AggregateVerificationError, antes de usar x_i.
def _board_snapshot(public_dir) -> dict:
    return {p.name: p.read_bytes() for p in sorted(public_dir.iterdir()) if p.is_file()}


def _refused_by_every_authority(scenario, election_data, aggregate_data, board_path, match,
                                **kwargs) -> list:
    """Nenhuma das 3 autoridades produz parcela; devolve as mensagens de recusa."""
    messages = []
    for authority in scenario.authorities:
        with pytest.raises(AggregateVerificationError, match=match) as info:
            compute_authority_partials(authority, election_data, aggregate_data,
                                       board_path=board_path, election_state="APURACAO",
                                       **kwargs)
        messages.append(str(info.value))
    return messages


def _published(public_dir) -> tuple:
    return (load_public_json(public_dir / "election.json"),
            load_public_json(public_dir / "aggregate_ciphertexts.json"))


@pytest.mark.parametrize("ballot_count", [1, len(VOTES)], ids=["ballot_count-1", "ballot_count-real"])
def test_single_ballot_sent_as_aggregate_is_refused(scenario, public_copy, ballot_count):
    """A cifra da cédula do eleitor-1 enviada como agregado: decifrada, revelaria o voto.

    Mesmo informando o ``ballot_count`` verdadeiro (3), as cifras não conferem
    com o produto do quadro. Nada é gravado.
    """
    election_data, _ = _published(public_copy)
    target = board_ciphertexts(read_board(public_copy))[0]  # eleitor-1
    forged = dict(_aggregate_data([target]), ballot_count=ballot_count)
    before = _board_snapshot(public_copy)

    messages = _refused_by_every_authority(
        scenario, election_data, forged, public_copy / BOARD_FILE,
        r"agregado recusado: difere do recalculado a partir do quadro público \(3 cédula\(s\)\): "
        r".*C1 e C2 de 'Alice'; C1 e C2 de 'Bob'$",
    )
    for message in messages:
        assert ("ballot_count informado 1, esperado 3" in message) == (ballot_count == 1)
    assert _board_snapshot(public_copy) == before


def test_aggregate_with_c2_multiplied_by_g_is_refused(scenario, public_copy):
    # C2·g = um voto a mais para Alice: só C2 de Alice difere.
    election_data, aggregate = _published(public_copy)
    alice = aggregate["ciphertexts"]["Alice"]
    alice["c2"] = str(int(alice["c2"]) * G % P)
    _refused_by_every_authority(scenario, election_data, aggregate, public_copy / BOARD_FILE,
                                r"\(3 cédula\(s\)\): C2 de 'Alice'$")


def test_aggregate_with_swapped_candidates_is_refused(scenario, public_copy):
    # As cifras de Alice no lugar das de Bob e vice-versa (inverteria o resultado).
    election_data, aggregate = _published(public_copy)
    ciphertexts = aggregate["ciphertexts"]
    ciphertexts["Alice"], ciphertexts["Bob"] = ciphertexts["Bob"], ciphertexts["Alice"]
    _refused_by_every_authority(scenario, election_data, aggregate, public_copy / BOARD_FILE,
                                r"\(3 cédula\(s\)\): C1 e C2 de 'Alice'; C1 e C2 de 'Bob'$")


@pytest.mark.parametrize(
    "change, match",
    [
        ("faltando", r"candidatos das cifras agregadas diferem dos da eleição: "
                     r"faltando \['Bob'\], sobrando \[\]"),
        ("sobrando", r"candidatos das cifras agregadas diferem dos da eleição: "
                     r"faltando \[\], sobrando \['Carol'\]"),
    ],
    ids=["candidato-faltando", "candidato-a-mais"],
)
def test_aggregate_with_missing_or_extra_candidate_is_refused(scenario, public_copy, change, match):
    election_data, aggregate = _published(public_copy)
    if change == "faltando":
        del aggregate["ciphertexts"]["Bob"]
    else:
        aggregate["ciphertexts"]["Carol"] = dict(aggregate["ciphertexts"]["Alice"])
    _refused_by_every_authority(scenario, election_data, aggregate, public_copy / BOARD_FILE, match)


@pytest.mark.parametrize("ballot_count", [len(VOTES) - 1, len(VOTES) + 1], ids=["menos", "mais"])
def test_aggregate_with_wrong_ballot_count_is_refused(scenario, public_copy, ballot_count):
    # Cifras corretas, contagem errada (afrouxaria ou apertaria o limite dos totais).
    election_data, aggregate = _published(public_copy)
    aggregate["ballot_count"] = ballot_count
    _refused_by_every_authority(
        scenario, election_data, aggregate, public_copy / BOARD_FILE,
        rf"\(3 cédula\(s\)\): ballot_count informado {ballot_count}, esperado 3$",
    )


def test_aggregate_without_ballot_count_is_refused(scenario, public_copy):
    election_data, aggregate = _published(public_copy)
    del aggregate["ballot_count"]
    _refused_by_every_authority(scenario, election_data, aggregate, public_copy / BOARD_FILE,
                                r"\(3 cédula\(s\)\): ballot_count ausente$")


@pytest.mark.parametrize("tamper", ["registro-alterado", "registro-intermediario-removido"])
def test_board_with_broken_hash_chain_is_refused(scenario, public_copy, tamper):
    """Cadeia quebrada: recusa mesmo com o agregado recalculado do quadro adulterado."""
    entries = read_board(public_copy)
    if tamper == "registro-alterado":
        cipher = entries[1]["ballot"]["ciphertexts"][0]
        cipher["c2"] = str(int(cipher["c2"]) * G % P)  # sem recalcular o hash
    else:
        del entries[1]  # sem renumerar nem refazer os elos
    write_board(public_copy, entries)
    election_data, _ = _published(public_copy)
    consistent = _aggregate_data(board_ciphertexts(entries))
    _refused_by_every_authority(scenario, election_data, consistent, public_copy / BOARD_FILE,
                                r"agregado recusado: quadro público inválido \(ChainIntegrityError: ")


def test_rechained_board_with_forged_ballots_is_refused_by_signature(scenario, public_copy):
    """Por que a autoridade verifica as assinaturas das cédulas.

    ``hash_record`` e ``genesis_hash`` são públicos: o servidor troca as
    cédulas do eleitor-2 e do eleitor-3 por cifras de 0 geradas por ele
    (valor conhecido), recalcula a cadeia e monta o agregado do quadro
    forjado. Cadeia íntegra e agregado igual ao produto do quadro: sem a
    assinatura, o total de Alice seria exatamente o voto do eleitor-1.
    """
    entries = read_board(public_copy)
    for entry in entries[1:]:
        entry["ballot"]["ciphertexts"] = [
            {"candidate_id": cid, "c1": str(c1), "c2": str(c2)}
            for cid, (c1, c2) in zip(CANDIDATES, [_encrypt(0, scenario.joint_key)
                                                  for _ in CANDIDATES])
        ]
    entries = _chain(entries)
    write_board(public_copy, entries)
    election_data, _ = _published(public_copy)
    consistent = _aggregate_data(board_ciphertexts(entries))
    assert consistent["ballot_count"] == len(VOTES)
    _refused_by_every_authority(
        scenario, election_data, consistent, public_copy / BOARD_FILE,
        r"agregado recusado: quadro público inválido \(InvalidBallotSignatureError: ",
    )


def test_board_with_ciphertext_copied_by_colluding_voter_is_refused(scenario, public_copy):
    """Eleitor conivente (eleitor-2) copia as cifras do eleitor-1 e assina com a PRÓPRIA chave.

    O servidor honesto recusa essa cédula no recebimento (``Election``: c1 já
    usado; ver ``test_server_voting.py``). Aqui o quadro foi montado por um
    servidor desonesto: assinatura e cadeia válidas, só o ``c1`` repetido
    denuncia a cópia (no produto, o voto do eleitor-1 contaria duas vezes).
    """
    entries = read_board(public_copy)
    copied = signed_ballot("eleitor-2", scenario.voter_keys["eleitor-2"],
                           board_ciphertexts(entries)[0])
    entries[1] = {"schema_version": 1, **copied}
    entries = _chain(entries)
    write_board(public_copy, entries)
    election_data, _ = _published(public_copy)
    consistent = _aggregate_data(board_ciphertexts(entries))
    _refused_by_every_authority(
        scenario, election_data, consistent, public_copy / BOARD_FILE,
        r"quadro público inválido \(entrada 1: c1 da cifra 0 repete o da entrada 0 \(cifra copiada\)\)",
    )


def test_correct_aggregate_is_accepted_and_tally_is_normal(scenario, public_copy, tmp_path):
    election_data, aggregate = _published(public_copy)
    partials = [
        compute_authority_partials(a, election_data, aggregate,
                                   board_path=public_copy / BOARD_FILE, election_state="APURACAO")
        for a in scenario.authorities
    ]
    result = _combine(election_data, aggregate, partials, tmp_path / "result.json")
    assert result["totals"] == {"Alice": 2, "Bob": 1}
    # Também com o checkpoint independente do quadro real.
    for authority in scenario.authorities:
        compute_authority_partials(authority, election_data, aggregate,
                                   board_path=public_copy / BOARD_FILE,
                                   expected_checkpoint=scenario.board.checkpoint,
                                   election_state="APURACAO")
    assert audit(public_copy).valid


def _alternative_board(scenario, directory, voter_id: str):
    """Quadro alternativo só com a cédula (genuína) de ``voter_id``, cadeia refeita."""
    directory.mkdir()
    entries = _chain([e for e in read_board(scenario.public_dir)
                      if e["ballot"]["voter_id"] == voter_id])
    write_board(directory, entries)
    return directory / BOARD_FILE, _aggregate_data(board_ciphertexts(entries))


def test_alternative_board_is_accepted_without_independent_checkpoint(scenario, tmp_path):
    """LIMITAÇÃO ASSUMIDA, documentada com o comportamento atual.

    A autoridade confia nos arquivos que lê: o quadro (``board_path``) e
    ``election.json``. Um servidor que controle esses arquivos pode
    apresentar a ela um quadro alternativo só com a cédula genuína do
    eleitor-2, com a cadeia recalculada (``hash_record`` e ``genesis_hash``
    são públicos). Cadeia, assinatura, elegibilidade, unicidade e produto
    conferem, ``ballot_count`` = 1, e as parcelas decifram o voto do
    eleitor-2. Sem um tamanho/hash final de referência, isso é
    indistinguível de uma eleição com um único votante.

    A correção exige um checkpoint de fonte independente
    (``expected_checkpoint``), a mesma exigida pela remoção da última cédula
    (cenário 4c): ver o teste seguinte.
    """
    board_path, forged = _alternative_board(scenario, tmp_path / "alternativo", "eleitor-2")
    election_data = load_public_json(scenario.public_dir / "election.json")
    partials = [
        compute_authority_partials(a, election_data, forged, board_path=board_path,
                                   election_state="APURACAO")
        for a in scenario.authorities
    ]
    result = _combine(election_data, forged, partials, tmp_path / "result.json")
    assert result["totals"] == {"Alice": 0, "Bob": 1}  # o voto do eleitor-2 vazou


def test_alternative_board_is_refused_with_independent_checkpoint(scenario, tmp_path):
    # O checkpoint do quadro real (3 registros) faz o papel do resumo preservado
    # por fonte independente do servidor.
    board_path, forged = _alternative_board(scenario, tmp_path / "alternativo", "eleitor-2")
    election_data = load_public_json(scenario.public_dir / "election.json")
    _refused_by_every_authority(
        scenario, election_data, forged, board_path,
        r"quadro público inválido \(ChainIntegrityError: Quadro diverge do tamanho ou hash "
        r"do checkpoint esperado",
        expected_checkpoint=scenario.board.checkpoint,
    )


# =============================================================================
# Cenário 9 — cópia re-randomizada da cédula de outro eleitor (sigilo)
# =============================================================================
def _rerandomize(pairs, h: int) -> list:
    """Multiplica cada cifra por uma cifra de 0, ``(g^s, h^s)``: mesmo ``m``, ``c1`` novo."""
    result = []
    for c1, c2 in pairs:
        s = 2 + secrets.randbelow(Q - 2)
        result.append((c1 * pow(G, s, P) % P, c2 * pow(h, s, P) % P))
    return result


def test_rerandomized_copy_of_another_voters_ballot_is_accepted(tmp_path, rsa_keys):
    """LIMITAÇÃO ASSUMIDA (sigilo), documentada com o comportamento atual.

    Ataque de cópia de cédula (Cortier e Smyth, contra o Helios). O eleitor-2,
    conivente, pega no quadro público as cifras do eleitor-1 (V) e as
    re-randomiza, multiplicando cada uma por uma cifra de 0. O ``c1`` muda,
    então a regra de ``c1`` repetido (servidor, autoridades e auditor) não
    pega a cópia; a cifra continua cifrando o mesmo voto de V, e o eleitor-2
    a assina com a PRÓPRIA chave. O servidor aceita, as autoridades decifram
    (o quadro confere) e o auditor aprova.

    O voto do eleitor-2 vira uma cópia do voto de V: o resultado se desloca na
    direção do voto de V (aqui, Alice ganha 1 voto). Com eleitores coniventes
    copiando a cédula de V, a diferença entre os totais revela o voto de V.

    A correção exigiria uma prova de conhecimento por cifra (de ``r``/``m``)
    ligada à identidade do eleitor (por exemplo, ``voter_id`` no desafio
    Fiat-Shamir), que o formato da cédula não transporta (mesma lacuna da
    prova 0/1).
    """
    sc = build_election(tmp_path, rsa_keys, votes={"eleitor-1": (1, 0), "eleitor-3": (0, 1)},
                        until="VOTACAO_ABERTA")
    target = next(e for e in read_board(sc.public_dir) if e["ballot"]["voter_id"] == "eleitor-1")
    original = board_ciphertexts([target])[0]
    copied = _rerandomize(original, sc.joint_key)
    assert all(new[0] != old[0] for new, old in zip(copied, original))  # c1 novo

    receipt = sc.service.receive_ballot(signed_ballot("eleitor-2", sc.voter_keys["eleitor-2"], copied))
    assert receipt is not None and sc.election.has_voted("eleitor-2")  # aceito

    sc.service.close_voting()
    sc.election.start_tally()
    result = publish_tally(sc.public_dir, sc.authorities,
                           [record.ciphertexts for record in sc.election.accepted_ballots],
                           election_state=sc.election.current_state)
    # Sem a cópia: Alice 1 x 1 Bob. A cópia soma exatamente o voto de V.
    assert result["totals"] == {"Alice": 2, "Bob": 1}
    report = audit(sc.public_dir)
    assert report.valid, report.format()  # comportamento atual: não detectado
