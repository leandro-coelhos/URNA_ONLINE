"""Testes da máquina de estados, elegibilidade e validação das cédulas.

Módulos reais, sem stubs
------------------------
Nada é substituído em ``sys.modules``. Os testes usam:

- ``src.crypto``: chaves RSA (``generate_signing_key``), cifragem
  (``encrypt_bit``) e o envelope assinado da cédula
  (``src.crypto.ballots.sign_ballot``), o ÚNICO formato aceito pela eleição;
- ``src.authorities.authority``: ``compute_joint_public_key`` e
  ``publish_joint_public_key``;
- ``src.server.registration.Registration``.

Para provar a ORDEM das verificações ("a assinatura nem chegou a ser
verificada"), ``election_mod.verify_signed_ballot`` é envolvido por um
``mock.Mock(wraps=<função real>)``: a verificação continua sendo a de
``src.crypto.ballots``; o mock só conta as chamadas.

Etapas oficiais (README, ``src.election.states``)::

    CONFIGURACAO -> CADASTRO -> VOTACAO_ABERTA -> ENCERRADA -> APURACAO -> AUDITADA

A exponenciação modular é o ``pow`` nativo, padrão do projeto; aqui ele serve
de oráculo (chave conjunta, apuração) e para montar valores fora do subgrupo.
"""

import base64
import copy
import dataclasses
import hashlib
import importlib
import json
import secrets
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.authorities.authority import (  # noqa: E402
    MIN_AUTHORITIES,
    compute_joint_public_key,
    publish_joint_public_key,
)
from src.crypto.ballots import BallotFormatError, sign_ballot  # noqa: E402
from src.crypto.bit_proof import prove_bit  # noqa: E402
from src.crypto.elgamal import encrypt_bit  # noqa: E402
from src.crypto.keys import public_key_to_pem  # noqa: E402
from src.crypto.signatures import generate_signing_key  # noqa: E402
from src.election.election import (  # noqa: E402
    RECEIPT_DOMAIN,
    AcceptedBallot,
    DuplicateVoteError,
    Election,
    IneligibleVoterError,
    InvalidBallotError,
    InvalidProofError,
    InvalidSignatureError,
    Receipt,
    VotingClosedError,
    compute_receipt,
)
from src.election.states import (  # noqa: E402
    NEXT_STATE,
    ElectionState,
    InvalidStateTransitionError,
    VotingPreconditionError,
)
from src.server.registration import Registration, RegistrationClosedError  # noqa: E402

election_mod = sys.modules["src.election.election"]
states_mod = sys.modules["src.election.states"]
election_pkg = importlib.import_module("src.election")
REAL_VERIFY = election_mod.verify_signed_ballot


# =============================================================================
# Grupo e constantes
# =============================================================================
# RFC 3526, grupo 14 (MODP 2048 bits): p primo seguro, q = (p-1)/2 primo e,
# como p ≡ 7 (mod 8), g = 2 é resíduo quadrático e gera o subgrupo de ordem q.
# Definido aqui de forma independente (oráculo), e não importado da crypto.
_RFC3526_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
GROUP = SimpleNamespace(p=_RFC3526_P, q=(_RFC3526_P - 1) // 2, g=2)
P, Q, G = GROUP.p, GROUP.q, GROUP.g

# Menor não-resíduo quadrático (a^q ≡ p - 1): fora do subgrupo de ordem q.
# Calculado, não fixado: evita supor um valor errado.
NON_RESIDUE = next(a for a in range(3, 1000) if pow(a, Q, P) == P - 1)

ELECTION_ID = "eleicao-2026"
CANDIDATES = ["Alice", "Bob"]
B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
OFFICIAL_STATES = ["CONFIGURACAO", "CADASTRO", "VOTACAO_ABERTA", "ENCERRADA", "APURACAO", "AUDITADA"]

_NO_PROOF_FIELD = (
    "O envelope de src.crypto.ballots não tem campo para a prova 0/1: sign_ballot "
    "recusa a cédula com prova (BallotFormatError). Quando src.crypto.bit_proof "
    "entrar no formato, este teste passa a executar e o xfail estrito obriga a "
    "atualizá-lo."
)


# =============================================================================
# Eleitor (cliente): chave RSA real e envelope assinado de src.crypto.ballots
# =============================================================================
@dataclasses.dataclass(frozen=True)
class VoterKey:
    public_key: str
    private: object = dataclasses.field(default=None, repr=False)


def _new_voter_key() -> VoterKey:
    private = generate_signing_key(2048)
    return VoterKey(public_key_to_pem(private.public_key()), private)


def _body(voter_id, ciphertexts, *, election_id=ELECTION_ID, candidates=CANDIDATES) -> dict:
    return {
        "schema_version": 1,
        "election_id": election_id,
        "voter_id": voter_id,
        "ciphertexts": [
            {"candidate_id": cid, "c1": str(c1), "c2": str(c2)}
            for cid, (c1, c2) in zip(candidates, ciphertexts)
        ],
    }


def _canonical(ballot: dict) -> bytes:
    """Oráculo independente do JSON canônico de src.crypto.ballots."""
    return json.dumps(ballot, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _pairs(envelope) -> list:
    return [(int(c["c1"]), int(c["c2"])) for c in envelope["ballot"]["ciphertexts"]]


@pytest.fixture(autouse=True)
def signature_spy(monkeypatch):
    """Conta as chamadas ao verificador REAL de src.crypto.ballots."""
    spy = mock.Mock(name="verify_signed_ballot", wraps=REAL_VERIFY)
    monkeypatch.setattr(election_mod, "verify_signed_ballot", spy)
    return spy


# =============================================================================
# Ambiente de teste
# =============================================================================
@dataclasses.dataclass
class Env:
    election: Election
    registration: object
    voter_keys: dict
    authority_xs: list
    public_data: dict
    election_path: Path
    ballots_path: Path
    signature_verifier: mock.Mock
    randomness: list = dataclasses.field(default_factory=list)

    def encrypt(self, m: int) -> tuple:
        """Cliente do eleitor: encrypt_bit real, (c1, c2) = (g^r, g^m · h^r mod p)."""
        ciphertext, r = encrypt_bit(m, self.election.joint_public_key, GROUP)
        self.randomness.append(r)
        return (ciphertext.a, ciphertext.b)

    def signed(self, voter_id, ciphertexts, *, key=None, election_id=ELECTION_ID):
        key = key if key is not None else self.voter_keys[voter_id]
        return sign_ballot(_body(voter_id, ciphertexts, election_id=election_id), key.private)

    def ballot(self, voter_id, votes=(1, 0), *, key=None):
        return self.signed(voter_id, [self.encrypt(m) for m in votes], key=key)

    def ballot_with_proofs(self, voter_id, votes=(1, 0), *, proofs=None):
        """Envelope com provas 0/1 REAIS (src.crypto.bit_proof) dentro da cédula.

        Hoje ``sign_ballot`` recusa (BallotFormatError): o formato não tem o
        campo. Usado pelos testes ``xfail`` estritos da prova de validade.
        """
        h = self.election.joint_public_key
        pairs, generated = [], []
        for m in votes:
            ciphertext, r = encrypt_bit(m, h, GROUP)
            pairs.append((ciphertext.a, ciphertext.b))
            proof = prove_bit(ciphertext, h, r, m, GROUP)
            generated.append({k: str(v) for k, v in dataclasses.asdict(proof).items()})
        body = _body(voter_id, pairs)
        body["proof"] = generated if proofs is None else proofs
        return sign_ballot(body, self.voter_keys[voter_id].private)


@pytest.fixture(scope="module")
def key_pool():
    # RSA de 2048 bits é lento; o mesmo conjunto serve a todos os testes.
    return [_new_voter_key() for _ in range(4)]


def _build(
    tmp_path,
    key_pool,
    *,
    n_voters=3,
    n_authorities=3,
    freeze=True,
    publish=True,
    open_voting=True,
) -> Env:
    election_path = tmp_path / "data" / "public" / "election.json"
    ballots_path = tmp_path / "data" / "public" / "accepted_ballots.json"

    election = Election(
        ELECTION_ID,
        GROUP,
        CANDIDATES,
        ballots_path=ballots_path,
    )
    registration = Registration(ELECTION_ID, p=P, q=Q, state_provider=election.current_state)

    voter_keys = {}
    for i in range(n_voters):
        voter_id = f"eleitor-{i + 1}"
        registration.register_voter(voter_id, key_pool[i].public_key)
        voter_keys[voter_id] = key_pool[i]

    # O teste faz o papel das autoridades: só h_i = g^x_i vai ao cadastro.
    xs = [2 + secrets.randbelow(Q - 2) for _ in range(n_authorities)]
    for i, x in enumerate(xs, start=1):
        registration.register_authority(str(i), pow(G, x, P))

    if freeze:
        registration.freeze()
    public_data = registration.export_public_data()
    if publish and n_authorities >= MIN_AUTHORITIES:
        publish_joint_public_key(public_data, GROUP, election_path)

    env = Env(
        election, registration, voter_keys, xs, public_data,
        election_path, ballots_path, election_mod.verify_signed_ballot,
    )
    if open_voting:
        election.open_voting(public_data, election_path=election_path)
    return env


@pytest.fixture
def env(tmp_path, key_pool):
    return _build(tmp_path, key_pool)


def _ballots_file(env) -> dict:
    return json.loads(env.ballots_path.read_text(encoding="utf-8"))


# =============================================================================
# Configuração
# =============================================================================
def test_group_parameters_are_rfc3526_2048():
    assert P.bit_length() == 2048
    assert Q.bit_length() >= 224
    assert P == 2 * Q + 1
    assert pow(G, Q, P) == 1 and G != 1
    assert pow(NON_RESIDUE, Q, P) == P - 1


def test_signature_verification_cannot_be_disabled(tmp_path, env, key_pool):
    """Antes: "signature_verifier é obrigatório". Hoje não há verificador injetável.

    A assinatura é sempre verificada com src.crypto.ballots: não existe
    parâmetro para trocá-la ou desligá-la, e a configuração padrão rejeita
    uma cédula forjada.
    """
    with pytest.raises(TypeError):
        Election(ELECTION_ID, GROUP, CANDIDATES, signature_verifier=lambda *a: True,
                 ballots_path=tmp_path / "b.json")
    with pytest.raises(InvalidSignatureError):
        env.election.submit_ballot(env.ballot("eleitor-1", key=key_pool[3]))
    assert env.signature_verifier.call_count == 1


@pytest.mark.xfail(strict=True, raises=TypeError, reason=_NO_PROOF_FIELD)
def test_require_proof_without_verifier_is_configuration_error(tmp_path):
    # Hoje a opção require_proof nem existe (TypeError).
    with pytest.raises(ValueError):
        Election(ELECTION_ID, GROUP, CANDIDATES, require_proof=True,
                 ballots_path=tmp_path / "b.json")


@pytest.mark.parametrize("candidates", [["Maria Silva", "Bob"], ["Alice", ""], ["Alice", "a/b"]],
                         ids=["espaco", "vazio", "barra"])
def test_candidate_ids_must_be_identifiers(tmp_path, candidates):
    # O candidate_id vai dentro da cédula assinada (src.crypto.ballots).
    with pytest.raises(ValueError, match="candidato inválido"):
        Election(ELECTION_ID, GROUP, candidates, ballots_path=tmp_path / "b.json")


def test_state_names_and_errors_are_shared_across_modules():
    # Os nomes movidos para states.py continuam importáveis dos lugares antigos.
    for name in ("ElectionError", "ElectionStateError", "InvalidStateTransitionError",
                 "VotingPreconditionError", "ElectionState", "NEXT_STATE"):
        assert getattr(election_mod, name) is getattr(states_mod, name)
        assert getattr(election_pkg, name) is getattr(states_mod, name)
    assert issubclass(VotingPreconditionError, InvalidStateTransitionError)
    assert issubclass(VotingClosedError, states_mod.ElectionStateError)
    assert issubclass(InvalidBallotError, states_mod.ElectionError)


def test_flat_ballot_format_was_removed():
    # Formato único: não resta serialização paralela da cédula.
    assert not hasattr(election_mod, "ballot_signing_payload")
    assert not hasattr(election_pkg, "ballot_signing_payload")


# =============================================================================
# Fluxo ponta a ponta
# =============================================================================
def _oracle_tally(env) -> list:
    """Oráculo de teste: decifra o produto com Σ x_i (as autoridades reais não fazem isso)."""
    x = sum(env.authority_xs) % Q
    totals = []
    for position in range(len(CANDIDATES)):
        c1 = c2 = 1
        for record in env.election.accepted_ballots:
            a, b = record.ciphertexts[position]
            c1, c2 = c1 * a % P, c2 * b % P
        g_total = c2 * pow(c1, Q - x, P) % P  # c2 / c1^x, pois c1^q ≡ 1
        n = len(env.election.accepted_ballots)
        totals.append(next(t for t in range(n + 1) if pow(G, t, P) == g_total))
    return totals


def test_end_to_end(tmp_path, key_pool):
    env = _build(tmp_path, key_pool, open_voting=False)
    assert env.election.current_state() == "CADASTRO"
    assert env.public_data["frozen"] is True
    assert len(env.public_data["authorities"]) == 3

    env.election.open_voting(env.public_data, election_path=env.election_path)
    assert env.election.current_state() == "VOTACAO_ABERTA"
    assert env.election.joint_public_key == pow(G, sum(env.authority_xs), P)  # oráculo

    votes = {"eleitor-1": (1, 0), "eleitor-2": (0, 1), "eleitor-3": (1, 0)}
    submitted, receipts = {}, []
    for voter_id, choice in votes.items():
        submitted[voter_id] = env.ballot(voter_id, choice)
        receipt = env.election.submit_ballot(submitted[voter_id])
        assert isinstance(receipt, Receipt)
        receipts.append(receipt)
    assert [r.index for r in receipts] == [0, 1, 2]
    assert [r.voter_id for r in receipts] == list(votes)

    env.election.close_voting()
    assert env.election.current_state() == "ENCERRADA"

    data = _ballots_file(env)
    assert data["schema_version"] == 2
    assert data["election_id"] == ELECTION_ID
    assert data["state"] == "ENCERRADA"
    assert data["candidates"] == CANDIDATES
    assert data["joint_public_key"] == str(env.election.joint_public_key)
    assert len(data["ballots"]) == 3
    for record, receipt, accepted in zip(data["ballots"], receipts, env.election.accepted_ballots):
        sent = submitted[record["voter_id"]]
        # Recibo recalculado por um oráculo independente do JSON canônico.
        expected = hashlib.sha256(
            RECEIPT_DOMAIN + _canonical(sent["ballot"]) + b"\n" + sent["signature"].encode("ascii")
        ).hexdigest()
        assert record == {
            "index": receipt.index,
            "voter_id": receipt.voter_id,
            "ballot": sent["ballot"],
            "signature": sent["signature"],
            "receipt": expected,
        }
        assert receipt.receipt == expected == compute_receipt(sent["ballot"], sent["signature"])
        # O envelope guardado é exatamente o enviado: é o que vai para o quadro.
        assert accepted.envelope() == sent
        assert accepted.ciphertexts == tuple(_pairs(sent))

    # As cifras guardadas continuam somando certo: 2 votos para Alice, 1 para Bob.
    assert _oracle_tally(env) == [2, 1]


def test_accepted_envelope_is_accepted_by_the_real_bulletin_board(env):
    """Formato único: a cédula aceita pela eleição é aceita pelo quadro real."""
    pytest.importorskip("fcntl", reason="src.bulletin_board.board usa fcntl (Linux, macOS ou WSL)")
    from src.bulletin_board.board import BulletinBoard

    voters = {v["voter_id"]: v["public_key_pem"] for v in env.public_data["voters"]}
    board = BulletinBoard.create(env.ballots_path.parent / "bulletin_board.jsonl",
                                 election_id=ELECTION_ID, candidate_ids=CANDIDATES,
                                 voter_public_keys=voters)
    env.election.submit_ballot(env.ballot("eleitor-1"))
    record = board.append(env.election.accepted_ballots[0].envelope())
    assert record["index"] == 0
    assert compute_receipt(record["ballot"], record["signature"]) == env.election.accepted_ballots[0].receipt


# =============================================================================
# Máquina de estados e state_provider
# =============================================================================
@pytest.mark.security
def test_next_state_is_the_official_linear_chain():
    states = list(ElectionState)
    assert [s.value for s in states] == OFFICIAL_STATES
    assert dict(NEXT_STATE) == {a: b for a, b in zip(states, states[1:])}
    assert ElectionState.AUDITADA not in NEXT_STATE          # terminal
    assert ElectionState.CONFIGURACAO not in NEXT_STATE.values()  # ninguém volta ao início
    with pytest.raises(TypeError):
        NEXT_STATE[ElectionState.AUDITADA] = ElectionState.CADASTRO  # somente leitura


@pytest.mark.security
def test_current_state_in_each_phase(tmp_path, key_pool):
    env = _build(tmp_path, key_pool, open_voting=False)
    election = env.election
    assert [s.value for s in ElectionState] == [
        "CONFIGURACAO", "CADASTRO", "VOTACAO_ABERTA", "ENCERRADA", "APURACAO", "AUDITADA"
    ]

    def reopen():
        election.open_voting(env.public_data, election_path=env.election_path)

    def assert_blocked(*transitions):
        for transition in transitions:
            with pytest.raises(InvalidStateTransitionError):
                transition()

    # A construção é a CONFIGURACAO: o objeto já nasce em CADASTRO.
    assert election.current_state() == "CADASTRO"
    assert election.state is ElectionState.CADASTRO
    assert_blocked(election.close_voting, election.start_tally, election.mark_audited)
    assert election.current_state() == "CADASTRO"
    assert not env.ballots_path.exists()

    reopen()
    assert election.current_state() == "VOTACAO_ABERTA"
    assert election.state is ElectionState.VOTACAO_ABERTA
    assert _ballots_file(env)["state"] == "VOTACAO_ABERTA"
    assert_blocked(reopen, election.start_tally, election.mark_audited)
    assert election.current_state() == "VOTACAO_ABERTA"

    election.close_voting()
    assert election.current_state() == "ENCERRADA"
    assert _ballots_file(env)["state"] == "ENCERRADA"
    assert_blocked(reopen, election.close_voting, election.mark_audited)
    assert election.current_state() == "ENCERRADA"

    election.start_tally()
    assert election.current_state() == "APURACAO"
    assert election.state is ElectionState.APURACAO
    assert _ballots_file(env)["state"] == "APURACAO"
    assert_blocked(reopen, election.close_voting, election.start_tally)
    assert election.current_state() == "APURACAO"

    election.mark_audited()
    assert election.current_state() == "AUDITADA"
    assert election.state is ElectionState.AUDITADA
    assert _ballots_file(env)["state"] == "AUDITADA"
    assert_blocked(reopen, election.close_voting, election.start_tally, election.mark_audited)
    assert election.current_state() == "AUDITADA"


def test_state_provider_drives_registration(tmp_path, key_pool):
    env = _build(tmp_path, key_pool, open_voting=False, freeze=False, publish=False)
    # Em CADASTRO o cadastro aceitou eleitores e autoridades.
    assert len(env.registration.export_public_data()["voters"]) == 3
    env.registration.freeze()
    data = env.registration.export_public_data()
    publish_joint_public_key(data, GROUP, env.election_path)
    env.election.open_voting(data, election_path=env.election_path)
    assert env.election.current_state() == "VOTACAO_ABERTA"
    with pytest.raises(RegistrationClosedError):
        env.registration.register_voter("eleitor-novo", key_pool[3].public_key)


@pytest.mark.security
def test_cadastro_to_encerrada_is_rejected(tmp_path, key_pool):
    env = _build(tmp_path, key_pool, open_voting=False)
    with pytest.raises(InvalidStateTransitionError):
        env.election.close_voting()
    assert env.election.current_state() == "CADASTRO"
    assert not env.ballots_path.exists()


@pytest.mark.security
def test_votacao_aberta_cannot_go_back(env):
    # Não existe API pública para voltar, e o estado não tem setter.
    with pytest.raises(AttributeError):
        env.election.state = ElectionState.CADASTRO
    # A regra interna de transição também recusa arestas para trás.
    for target in (ElectionState.CADASTRO, ElectionState.CONFIGURACAO):
        with pytest.raises(InvalidStateTransitionError):
            env.election._require_next(target)
    assert env.election.current_state() == "VOTACAO_ABERTA"


def test_open_twice_is_rejected(env):
    with pytest.raises(InvalidStateTransitionError):
        env.election.open_voting(env.public_data, election_path=env.election_path)
    assert env.election.current_state() == "VOTACAO_ABERTA"


@pytest.mark.security
def test_close_twice_and_reopen_are_rejected(env):
    env.election.close_voting()
    with pytest.raises(InvalidStateTransitionError):
        env.election.close_voting()
    with pytest.raises(InvalidStateTransitionError):
        env.election.open_voting(env.public_data, election_path=env.election_path)
    assert env.election.current_state() == "ENCERRADA"


# =============================================================================
# Pré-condições de CADASTRO -> VOTACAO_ABERTA
# =============================================================================
def _assert_cannot_open(env, public_data=None, *, match=None, **kwargs):
    data = env.public_data if public_data is None else public_data
    with pytest.raises(VotingPreconditionError, match=match):
        env.election.open_voting(data, **kwargs)
    # Nenhum efeito colateral: continua em CADASTRO e nada foi gravado.
    assert env.election.current_state() == "CADASTRO"
    assert env.election.joint_public_key is None
    assert not env.ballots_path.exists()


def test_open_requires_frozen_registration(tmp_path, key_pool):
    env = _build(tmp_path, key_pool, freeze=False, open_voting=False)
    assert env.public_data["frozen"] is False
    _assert_cannot_open(env, match="congelado")
    _assert_cannot_open(env, election_path=env.election_path)


def test_open_rejects_key_published_before_freeze(tmp_path, key_pool):
    env = _build(tmp_path, key_pool, freeze=False, open_voting=False)
    env.registration.freeze()
    frozen_data = env.registration.export_public_data()
    _assert_cannot_open(env, frozen_data, match="antes do congelamento",
                        election_path=env.election_path)


@pytest.mark.parametrize("n_authorities", [0, 1, 2])
def test_open_requires_three_authorities(tmp_path, key_pool, n_authorities):
    env = _build(tmp_path, key_pool, n_authorities=n_authorities, open_voting=False)
    assert len(env.public_data["authorities"]) == n_authorities
    _assert_cannot_open(env, match="autoridades")


def test_open_rejects_missing_authorities_list(tmp_path, key_pool):
    env = _build(tmp_path, key_pool, open_voting=False)
    data = copy.deepcopy(env.public_data)
    del data["authorities"]
    _assert_cannot_open(env, data)


def test_open_rejects_missing_published_file(tmp_path, key_pool):
    env = _build(tmp_path, key_pool, publish=False, open_voting=False)
    assert not env.election_path.exists()
    _assert_cannot_open(env, match="não existe", election_path=env.election_path)


def test_open_rejects_published_file_without_joint_key(tmp_path, key_pool):
    env = _build(tmp_path, key_pool, open_voting=False)
    published = json.loads(env.election_path.read_text())
    del published["joint_public_key"]
    env.election_path.write_text(json.dumps(published))
    _assert_cannot_open(env, match="joint_public_key", election_path=env.election_path)


def test_open_rejects_published_joint_key_that_differs(tmp_path, key_pool):
    env = _build(tmp_path, key_pool, open_voting=False)
    published = json.loads(env.election_path.read_text())
    published["joint_public_key"] = str(pow(G, 12345, P))
    env.election_path.write_text(json.dumps(published))
    _assert_cannot_open(env, match="joint_public_key", election_path=env.election_path)


@pytest.mark.parametrize("target", [1, P - 1, NON_RESIDUE], ids=["um", "p-1", "nao-residuo"])
def test_open_rejects_joint_key_outside_subgroup(tmp_path, key_pool, target):
    # Três chaves em (1, p) — aceitas por compute_joint_public_key — cujo
    # produto é o alvo: 4 · 4 · (alvo · 16⁻¹) ≡ alvo (mod p).
    env = _build(tmp_path, key_pool, open_voting=False)
    data = copy.deepcopy(env.public_data)
    third = target * pow(16, -1, P) % P
    data["authorities"] = [
        {"authority_id": "1", "public_key": "4"},
        {"authority_id": "2", "public_key": "4"},
        {"authority_id": "3", "public_key": str(third)},
    ]
    assert compute_joint_public_key(data, GROUP, min_authorities=3) == target
    _assert_cannot_open(env, data, match="subgrupo")


def test_open_rejects_registration_of_other_election(tmp_path, key_pool):
    env = _build(tmp_path, key_pool, open_voting=False)
    data = copy.deepcopy(env.public_data)
    data["election_id"] = "outra-eleicao"
    _assert_cannot_open(env, data, match="outra eleição")


def test_open_refuses_to_overwrite_existing_ballots_file(tmp_path, key_pool):
    env = _build(tmp_path, key_pool, open_voting=False)
    env.ballots_path.parent.mkdir(parents=True, exist_ok=True)
    env.ballots_path.write_text('{"ballots": ["de outra execução"]}')
    with pytest.raises(VotingPreconditionError):
        env.election.open_voting(env.public_data)
    assert env.ballots_path.read_text() == '{"ballots": ["de outra execução"]}'
    assert env.election.current_state() == "CADASTRO"


# =============================================================================
# Janela de votação
# =============================================================================
def test_vote_rejected_in_cadastro(tmp_path, key_pool):
    env = _build(tmp_path, key_pool, open_voting=False)
    envelope = {
        "ballot": _body("eleitor-1", [(4, 4), (16, 16)]),
        "signature": "AAAA",
    }
    with pytest.raises(VotingClosedError):
        env.election.submit_ballot(envelope)
    assert env.election.accepted_ballots == ()


@pytest.mark.security
@pytest.mark.parametrize("phase", ["ENCERRADA", "APURACAO", "AUDITADA"])
def test_vote_rejected_after_voting_closes(env, phase):
    ballot = env.ballot("eleitor-1")  # preparada enquanto a votação estava aberta
    env.election.close_voting()
    if phase in ("APURACAO", "AUDITADA"):
        env.election.start_tally()
    if phase == "AUDITADA":
        env.election.mark_audited()
    assert env.election.current_state() == phase
    with pytest.raises(VotingClosedError):
        env.election.submit_ballot(ballot)
    assert env.election.accepted_ballots == ()
    assert _ballots_file(env)["ballots"] == []


# =============================================================================
# Elegibilidade e voto único
# =============================================================================
@pytest.mark.security
def test_ineligible_voter_rejected(env, key_pool):
    calls_before = env.signature_verifier.call_count
    ballot = env.ballot("intruso", key=key_pool[3])
    with pytest.raises(IneligibleVoterError):
        env.election.submit_ballot(ballot)
    # A elegibilidade vem antes da assinatura: nem chegou a verificar.
    assert env.signature_verifier.call_count == calls_before
    assert env.election.accepted_ballots == ()


@pytest.mark.security
def test_duplicate_vote_rejected_and_original_preserved(env):
    first = env.ballot("eleitor-1", (1, 0))
    receipt = env.election.submit_ballot(first)
    file_before = env.ballots_path.read_text()
    memory_before = env.election.accepted_ballots
    calls_before = env.signature_verifier.call_count

    for second in (env.ballot("eleitor-1", (0, 1)), first):  # voto novo e reenvio
        with pytest.raises(DuplicateVoteError):
            env.election.submit_ballot(second)

    assert env.election.accepted_ballots == memory_before
    assert env.ballots_path.read_text() == file_before
    assert env.election.accepted_ballots[0].receipt == receipt.receipt
    assert env.election.accepted_ballots[0].ciphertexts == tuple(_pairs(first))
    assert env.signature_verifier.call_count == calls_before


@pytest.mark.parametrize("voter_id", ["../evil", "a/b", "", True, 123, None, " eleitor-1", "eleitor-1\n"])
def test_malformed_voter_id_rejected(env, voter_id):
    ballot = env.ballot("eleitor-1")
    ballot["ballot"]["voter_id"] = voter_id
    with pytest.raises(InvalidBallotError):
        env.election.submit_ballot(ballot)
    assert env.election.accepted_ballots == ()


def test_rejected_ballot_does_not_consume_the_vote(env, key_pool):
    forged = env.ballot("eleitor-1", key=key_pool[3])
    with pytest.raises(InvalidSignatureError):
        env.election.submit_ballot(forged)
    assert not env.election.has_voted("eleitor-1")
    env.election.submit_ballot(env.ballot("eleitor-1"))
    assert env.election.has_voted("eleitor-1")


# =============================================================================
# Validação estrutural do envelope e da cédula
# =============================================================================
@pytest.mark.parametrize("level, field", [
    ("envelope", "ballot"), ("envelope", "signature"),
    ("ballot", "schema_version"), ("ballot", "election_id"),
    ("ballot", "voter_id"), ("ballot", "ciphertexts"),
])
def test_missing_field_rejected(env, level, field):
    envelope = env.ballot("eleitor-1")
    target = envelope if level == "envelope" else envelope["ballot"]
    del target[field]
    with pytest.raises(InvalidBallotError, match="ausentes"):
        env.election.submit_ballot(envelope)


def _with_ballot(envelope, **changes):
    return {**envelope, "ballot": {**envelope["ballot"], **changes}}


def _with_ciphertexts(envelope, ciphertexts):
    return _with_ballot(envelope, ciphertexts=ciphertexts)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: "não é dict",
        lambda e: [e],
        lambda e: {**e, "extra": "contrabando"},
        lambda e: _with_ballot(e, extra="contrabando"),
        lambda e: {**e, "ballot": "não é dict"},
        lambda e: _with_ballot(e, election_id="outra-eleicao"),
        lambda e: _with_ballot(e, schema_version=2),
        lambda e: _with_ballot(e, schema_version=True),
        lambda e: _with_ciphertexts(e, e["ballot"]["ciphertexts"][:1]),
        lambda e: _with_ciphertexts(e, e["ballot"]["ciphertexts"] * 2),
        lambda e: _with_ciphertexts(e, "lista"),
        lambda e: _with_ciphertexts(e, [["4", "4"], ["16", "16"]]),
        lambda e: _with_ciphertexts(e, [{"candidate_id": "Alice", "c1": "4"},
                                        e["ballot"]["ciphertexts"][1]]),
        lambda e: _with_ciphertexts(e, list(reversed(e["ballot"]["ciphertexts"]))),
        lambda e: _with_ciphertexts(e, [{**e["ballot"]["ciphertexts"][0], "candidate_id": "Carol"},
                                        e["ballot"]["ciphertexts"][1]]),
    ],
    ids=["nao-dict", "lista", "campo-extra-envelope", "campo-extra-cedula", "cedula-nao-dict",
         "outra-eleicao", "versao-2", "versao-bool", "cifras-a-menos", "cifras-a-mais",
         "cifras-str", "cifras-lista", "sem-c2", "ordem-dos-candidatos", "candidato-inexistente"],
)
def test_malformed_ballot_rejected(env, mutate):
    with pytest.raises(InvalidBallotError):
        env.election.submit_ballot(mutate(env.ballot("eleitor-1")))
    assert env.election.accepted_ballots == ()


@pytest.mark.parametrize("bad", [True, False, 4], ids=["True", "False", "int"])
@pytest.mark.parametrize("field", ["c1", "c2"])
def test_non_string_component_rejected_before_signature(env, field, bad):
    # Antes: "bool disfarçado de int". No formato único, c1/c2 são strings
    # decimais: bool e até int (outra representação dos bytes assinados) são
    # recusados antes de verificar a assinatura.
    ballot = env.ballot("eleitor-1")
    ballot["ballot"]["ciphertexts"][0][field] = bad
    calls_before = env.signature_verifier.call_count
    with pytest.raises(InvalidBallotError, match="string decimal"):
        env.election.submit_ballot(ballot)
    assert env.signature_verifier.call_count == calls_before


@pytest.mark.parametrize("bad", [4.0, None, [4], "04", "+4", " 4", "4 ", "0x4", "4_0"],
                         ids=["float", "None", "lista", "zero-a-esquerda", "sinal", "espaco-antes",
                              "espaco-depois", "hex", "sublinhado"])
def test_non_canonical_decimal_component_rejected(env, bad):
    ballot = env.ballot("eleitor-1")
    ballot["ballot"]["ciphertexts"][1]["c2"] = bad
    with pytest.raises(InvalidBallotError, match="string decimal"):
        env.election.submit_ballot(ballot)


@pytest.mark.parametrize("bad, match", [
    ("-5", "string decimal"), ("0", "string decimal"),   # nem são decimais positivos
    ("1", r"\[2, p-1\]"), (str(P), r"\[2, p-1\]"), (str(P + 1), r"\[2, p-1\]"),
], ids=["-5", "0", "1", "P", "P+1"])
@pytest.mark.parametrize("field", ["c1", "c2"])
def test_component_outside_range_rejected(env, field, bad, match):
    ballot = env.ballot("eleitor-1")
    ballot["ballot"]["ciphertexts"][1][field] = bad
    with pytest.raises(InvalidBallotError, match=match):
        env.election.submit_ballot(ballot)


@pytest.mark.parametrize("bad", [1, P - 1, NON_RESIDUE], ids=["um", "p-1", "nao-residuo"])
@pytest.mark.parametrize("field", [0, 1], ids=["c1", "c2"])
def test_component_outside_subgroup_rejected_even_if_signed(env, field, bad):
    # Cédula corretamente assinada: a rejeição vem da checagem matemática
    # (intervalo para 1; subgrupo para p-1 e o não-resíduo).
    good, other = env.encrypt(1), env.encrypt(0)
    tampered = list(good)
    tampered[field] = bad
    ballot = env.signed("eleitor-1", [tuple(tampered), other])
    with pytest.raises(InvalidBallotError):
        env.election.submit_ballot(ballot)
    assert not env.election.has_voted("eleitor-1")


def test_subgroup_error_message_for_signed_non_residue(env):
    good, other = env.encrypt(1), env.encrypt(0)
    ballot = env.signed("eleitor-1", [(NON_RESIDUE, good[1]), other])
    with pytest.raises(InvalidBallotError, match="subgrupo"):
        env.election.submit_ballot(ballot)


def test_reused_randomness_within_ballot_rejected(env):
    c1, c2 = env.encrypt(1)
    ballot = env.signed("eleitor-1", [(c1, c2), (c1, c2 * G % P)])
    with pytest.raises(InvalidBallotError, match="repetido"):
        env.election.submit_ballot(ballot)


def test_copied_ciphertext_from_other_voter_rejected(env):
    original = env.ballot("eleitor-1")
    env.election.submit_ballot(original)
    copied = env.signed("eleitor-2", _pairs(original))
    with pytest.raises(InvalidBallotError, match="já usado"):
        env.election.submit_ballot(copied)
    assert not env.election.has_voted("eleitor-2")


# =============================================================================
# Assinatura digital (src.crypto.ballots.verify_signed_ballot)
# =============================================================================
@pytest.mark.security
def test_tampered_ciphertext_after_signing_rejected(env):
    ballot = env.ballot("eleitor-1", (1, 0))
    # Troca o voto de candidato: as cifras mudam de lugar, os candidate_id não.
    first, second = ballot["ballot"]["ciphertexts"]
    for name in ("c1", "c2"):
        first[name], second[name] = second[name], first[name]
    with pytest.raises(InvalidSignatureError):
        env.election.submit_ballot(ballot)
    assert issubclass(InvalidSignatureError, InvalidBallotError)


@pytest.mark.security
def test_ballot_signed_by_another_voter_rejected(env):
    ballot = env.ballot("eleitor-1", key=env.voter_keys["eleitor-2"])
    with pytest.raises(InvalidSignatureError):
        env.election.submit_ballot(ballot)


def test_signature_checked_with_registered_key_only(env):
    env.election.submit_ballot(env.ballot("eleitor-2"))
    registered = {
        v["voter_id"]: v.get("public_key", v.get("public_key_pem"))
        for v in env.public_data["voters"]
    }
    (envelope,), kwargs = env.signature_verifier.call_args
    # Só a chave CADASTRADA deste eleitor chega ao verificador.
    assert kwargs["voter_public_keys"] == {"eleitor-2": registered["eleitor-2"]}
    assert kwargs["election_id"] == ELECTION_ID
    assert tuple(kwargs["candidate_ids"]) == tuple(CANDIDATES)
    assert envelope["ballot"]["voter_id"] == "eleitor-2"


@pytest.mark.security
@pytest.mark.parametrize("signature", ["", "!!!!", "QQ", 123, None, True, b"QUJD", "A" * 5000])
def test_malformed_signature_rejected(env, signature):
    ballot = env.ballot("eleitor-1")
    ballot["signature"] = signature
    with pytest.raises(InvalidSignatureError):
        env.election.submit_ballot(ballot)


def test_non_canonical_base64_signature_rejected(env):
    ballot = env.ballot("eleitor-1")
    sig = ballot["signature"]
    pad = len(sig) - len(sig.rstrip("="))
    assert pad in (1, 2), "assinatura sem padding: ajuste o tamanho do teste"
    unused_bits = {1: 2, 2: 4}[pad]
    idx = B64_ALPHABET.index(sig[-pad - 1])
    mask = (1 << unused_bits) - 1
    variant = sig[: -pad - 1] + B64_ALPHABET[(idx & ~mask) | ((idx + 1) & mask)] + "=" * pad
    assert variant != sig and base64.b64decode(variant) == base64.b64decode(sig)
    ballot["signature"] = variant
    with pytest.raises(InvalidSignatureError, match="canônico"):
        env.election.submit_ballot(ballot)


@pytest.mark.parametrize("result", [False, True, 1, "True", None, mock.sentinel.ok, {"outra": 1}],
                         ids=["False", "True", "1", "str", "None", "sentinela", "outra-cedula"])
def test_signature_verifier_must_return_exactly_the_ballot(env, monkeypatch, result):
    # O verificador real devolve a cédula autenticada; qualquer outro retorno
    # (inclusive True) é rejeitado.
    monkeypatch.setattr(election_mod, "verify_signed_ballot", mock.Mock(return_value=result))
    with pytest.raises(InvalidSignatureError):
        env.election.submit_ballot(env.ballot("eleitor-1"))
    assert not env.election.has_voted("eleitor-1")


def test_signature_verifier_exception_is_invalid_signature(env, monkeypatch):
    verifier = mock.Mock(side_effect=RuntimeError("falha interna"))
    monkeypatch.setattr(election_mod, "verify_signed_ballot", verifier)
    with pytest.raises(InvalidSignatureError):
        env.election.submit_ballot(env.ballot("eleitor-1"))
    verifier.assert_called_once()


# =============================================================================
# Prova ZKP 0/1
#
# O envelope não tem campo para a prova (limitação documentada; cenário 7 da
# T14). O que se verifica hoje: uma prova acrescentada à cédula não é aceita
# em silêncio. Os cenários com prova ficam como xfail estrito, com provas
# REAIS de src.crypto.bit_proof.
# =============================================================================
@pytest.mark.parametrize("where", ["cedula", "envelope"])
def test_proof_field_is_rejected_not_silently_accepted(env, where):
    # Antes: "prova sem verificador é rejeitada". Hoje nenhuma prova trafega:
    # o campo extra é recusado (não estaria coberto pelo formato assinado).
    ballot = env.ballot("eleitor-1")
    target = ballot["ballot"] if where == "cedula" else ballot
    target["proof"] = {"scheme": "qualquer"}
    calls_before = env.signature_verifier.call_count
    with pytest.raises(InvalidBallotError, match="desconhecidos"):
        env.election.submit_ballot(ballot)
    assert env.signature_verifier.call_count == calls_before
    assert not env.election.has_voted("eleitor-1")


@pytest.mark.xfail(strict=True, raises=BallotFormatError, reason=_NO_PROOF_FIELD)
def test_valid_proof_accepted_with_expected_arguments(env):
    ballot = env.ballot_with_proofs("eleitor-1")
    env.election.submit_ballot(ballot)
    pytest.fail("atualize: verificar que a prova foi conferida com as cifras e h corretos")


@pytest.mark.xfail(strict=True, raises=BallotFormatError, reason=_NO_PROOF_FIELD)
def test_invalid_proof_rejected(env):
    wrong = [{"challenge_0": "0"}, {"challenge_0": "0"}]
    with pytest.raises(InvalidProofError):
        env.election.submit_ballot(env.ballot_with_proofs("eleitor-1", proofs=wrong))


@pytest.mark.xfail(strict=True, raises=BallotFormatError, reason=_NO_PROOF_FIELD)
@pytest.mark.parametrize("behavior", [1, "True", RuntimeError("x")], ids=["1", "str", "excecao"])
def test_proof_verifier_must_return_exactly_true(env, behavior):
    ballot = env.ballot_with_proofs("eleitor-1")
    pytest.fail(f"atualize: verificador de prova que devolve {behavior!r} deve rejeitar {ballot}")


@pytest.mark.xfail(strict=True, raises=BallotFormatError, reason=_NO_PROOF_FIELD)
def test_required_proof_missing_rejected(env):
    env.ballot_with_proofs("eleitor-1")  # o formato precisa aceitar provas primeiro
    with pytest.raises(InvalidProofError, match="exige"):
        env.election.submit_ballot(env.ballot("eleitor-1"))


@pytest.mark.xfail(strict=True, raises=BallotFormatError, reason=_NO_PROOF_FIELD)
@pytest.mark.parametrize("mutate", [
    lambda b: b["ballot"].pop("proof"),
    lambda b: b["ballot"].__setitem__("proof", []),
], ids=["removida", "trocada"])
def test_proof_changed_after_signing_rejected(env, mutate):
    ballot = env.ballot_with_proofs("eleitor-1")
    mutate(ballot)
    with pytest.raises(InvalidSignatureError):
        env.election.submit_ballot(ballot)


# =============================================================================
# Persistência segura e imutabilidade
# =============================================================================
def test_persistence_failure_does_not_record_vote(env):
    ballot = env.ballot("eleitor-1")
    with mock.patch.object(election_mod.os, "replace", side_effect=OSError("disco cheio")):
        with pytest.raises(OSError):
            env.election.submit_ballot(ballot)
    assert env.election.accepted_ballots == ()
    assert not env.election.has_voted("eleitor-1")
    assert [p.name for p in env.ballots_path.parent.iterdir() if p.suffix == ".tmp"] == []
    assert _ballots_file(env)["ballots"] == []

    env.election.submit_ballot(ballot)  # o eleitor pode reenviar
    assert env.election.has_voted("eleitor-1")


@pytest.mark.parametrize(
    "prepare, transition, expected",
    [
        ([], "close_voting", "VOTACAO_ABERTA"),
        (["close_voting"], "start_tally", "ENCERRADA"),
        (["close_voting", "start_tally"], "mark_audited", "APURACAO"),
    ],
    ids=["encerrar", "apurar", "auditar"],
)
def test_transition_persistence_failure_keeps_state(env, prepare, transition, expected):
    for step in prepare:
        getattr(env.election, step)()
    with mock.patch.object(election_mod.os, "replace", side_effect=OSError("x")):
        with pytest.raises(OSError):
            getattr(env.election, transition)()
    assert env.election.current_state() == expected
    assert _ballots_file(env)["state"] == expected


def test_accepted_ballots_are_immutable(env):
    ballot = env.ballot("eleitor-1")
    env.election.submit_ballot(ballot)

    record = env.election.accepted_ballots[0]
    assert isinstance(env.election.accepted_ballots, tuple)
    assert isinstance(record, AcceptedBallot)
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.voter_id = "outro"

    original = copy.deepcopy(ballot)
    # Alterar o envelope enviado, a exportação ou o envelope devolvido não
    # muda a cédula registrada.
    ballot["ballot"]["ciphertexts"][0]["c1"] = "4"
    ballot["signature"] = "adulterada"
    exported = record.to_dict()
    exported["ballot"]["ciphertexts"][0]["c1"] = "4"
    envelope = record.envelope()
    envelope["ballot"]["voter_id"] = "outro"
    assert record.to_dict()["ballot"] == original["ballot"]
    assert record.envelope() == original
    assert record.ciphertexts[0][0] != 4


# =============================================================================
# Isolamento de segredos
# =============================================================================
def test_no_secrets_in_public_files(tmp_path, key_pool):
    env = _build(tmp_path, key_pool)
    for voter_id in env.voter_keys:
        env.election.submit_ballot(env.ballot(voter_id))
    env.election.close_voting()
    env.election.start_tally()
    env.election.mark_audited()

    xs = env.authority_xs
    secret_values = {str(x) for x in xs} | {str(sum(xs)), str(sum(xs) % Q)}
    secret_values |= {str(r) for r in env.randomness}
    for key in key_pool:
        numbers = key.private.private_numbers()
        secret_values |= {str(numbers.d), str(numbers.p), str(numbers.q)}

    public_dir = env.ballots_path.parent
    assert sorted(p.name for p in public_dir.iterdir()) == ["accepted_ballots.json", "election.json"]
    for path in public_dir.iterdir():
        text = path.read_text(encoding="utf-8")
        assert "PRIVATE KEY" not in text
        assert '"x"' not in text
        for secret in secret_values:
            assert secret not in text, f"segredo vazou em {path.name}"

    # Nem o estado em memória do objeto Election guarda segredos.
    state_repr = repr(vars(env.election))
    for secret in secret_values:
        assert secret not in state_repr


def test_election_rejects_private_key_in_registration(tmp_path, key_pool):
    env = _build(tmp_path, key_pool, open_voting=False)
    data = copy.deepcopy(env.public_data)
    field = "public_key" if "public_key" in data["voters"][0] else "public_key_pem"
    data["voters"][0][field] = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
    _assert_cannot_open(env, data, match="chave privada")