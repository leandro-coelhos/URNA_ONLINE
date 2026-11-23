"""Testes da camada de serviço de votação (``src.server.voting``).

``VotingService`` só orquestra: as regras da eleição já têm testes em
``test_election_voting.py``. Aqui verificamos o fluxo, a integração com o
quadro público e a propagação das exceções.

Independência de branch: ``src.crypto.group`` e ``src.authorities.authority``
recebem stubs apenas se não existirem. O cadastro é simulado com o dicionário
no formato de ``export_public_data()``, e a assinatura usa um verificador
determinístico baseado em SHA-256, injetado explicitamente.
"""

import base64
import copy
import dataclasses
import hashlib
import importlib
import json
import secrets
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Protocol, runtime_checkable
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# =============================================================================
# Independência de branch
# =============================================================================
def _ensure_package(name: str) -> types.ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    try:
        return importlib.import_module(name)
    except ImportError:
        package = types.ModuleType(name)
        package.__path__ = []
        sys.modules[name] = package
        parent, _, child = name.rpartition(".")
        if parent:
            setattr(_ensure_package(parent), child, package)
        return package


def _install_stub(name: str, **attrs) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules[name] = module
    parent, _, child = name.rpartition(".")
    setattr(_ensure_package(parent), child, module)
    return module


try:
    from src.crypto.group import mod_exp as MOD_EXP
except ImportError:
    MOD_EXP = mock.Mock(name="mod_exp", side_effect=lambda b, e, m: pow(b, e, m))
    if "src.crypto.group" in sys.modules:
        sys.modules["src.crypto.group"].mod_exp = MOD_EXP
    else:
        _install_stub("src.crypto.group", mod_exp=MOD_EXP)

try:
    import src.authorities.authority  # noqa: F401
except ImportError:

    @runtime_checkable
    class _StubGroupParams(Protocol):
        p: int
        q: int
        g: int

    class _StubJointKeyError(ValueError):
        pass

    def _stub_compute(public_data, group, *, min_authorities=3):
        authorities = public_data.get("authorities") if isinstance(public_data, dict) else None
        if not isinstance(authorities, list) or len(authorities) < min_authorities:
            raise _StubJointKeyError("autoridades insuficientes")
        h = 1
        for entry in authorities:
            value = entry.get("public_key") if isinstance(entry, dict) else None
            if not isinstance(value, str) or not value.isascii() or not value.isdigit():
                raise _StubJointKeyError("public_key não decimal")
            h_i = int(value)
            if not 1 < h_i < group.p:
                raise _StubJointKeyError("public_key fora de (1, p)")
            h = h * h_i % group.p
        return h

    def _stub_publish(public_data, group, election_path, *, min_authorities=3):
        h = _stub_compute(public_data, group, min_authorities=min_authorities)
        path = Path(election_path)
        data = json.loads(path.read_text()) if path.exists() else {}
        data.update(copy.deepcopy(public_data))
        data["group"] = {"p": str(group.p), "q": str(group.q), "g": str(group.g)}
        data["joint_public_key"] = str(h)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=True))
        return data

    _install_stub(
        "src.authorities.authority",
        MIN_AUTHORITIES=3,
        GroupParams=_StubGroupParams,
        JointKeyError=_StubJointKeyError,
        compute_joint_public_key=_stub_compute,
        publish_joint_public_key=_stub_publish,
    )

from src.election.election import AcceptedBallot, Election, ballot_signing_payload  # noqa: E402
from src.election.states import ElectionState  # noqa: E402
from src.server.voting import (  # noqa: E402
    BoardPublicationError,
    DuplicateVoteError,
    IneligibleVoterError,
    InvalidBallotError,
    InvalidProofError,
    InvalidSignatureError,
    InvalidStateTransitionError,
    Receipt,
    VotingClosedError,
    VotingPreconditionError,
    VotingService,
)

election_mod = sys.modules["src.election.election"]
states_mod = sys.modules["src.election.states"]
voting_mod = sys.modules["src.server.voting"]


# =============================================================================
# Grupo, chaves e assinatura determinística
# =============================================================================
# RFC 3526, grupo 14 (MODP 2048 bits); g = 2 gera o subgrupo de ordem q.
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

ELECTION_ID = "eleicao-2026"
CANDIDATES = ["Alice", "Bob"]


def _new_public_key(label: str) -> str:
    return f"-----BEGIN PUBLIC KEY-----\nSTUB-{label}-{secrets.token_hex(8)}\n-----END PUBLIC KEY-----\n"


INTRUDER_KEY = _new_public_key("intruso")


def _sign(public_key: str, payload: bytes) -> bytes:
    """Stub determinístico: só serve para testar o fluxo, não é assinatura real."""
    return hashlib.sha256(public_key.encode("ascii") + payload).digest()


def verify_signature_stub(public_key: str, message: bytes, signature: bytes) -> bool:
    return signature == _sign(public_key, message)


# =============================================================================
# Ambiente
# =============================================================================
@dataclasses.dataclass
class World:
    public_data: dict
    voter_keys: dict
    authority_xs: list
    ballots_path: Path
    election_path: Path

    @property
    def joint_key(self) -> int:
        return pow(G, sum(self.authority_xs), P)


def _make_world(tmp_path, *, frozen=True, n_authorities=3) -> World:
    voter_keys = {f"eleitor-{i}": _new_public_key(f"eleitor-{i}") for i in (1, 2, 3)}
    xs = [2 + secrets.randbelow(Q - 2) for _ in range(n_authorities)]
    public_data = {
        "schema_version": 1,
        "election_id": ELECTION_ID,
        "frozen": frozen,
        "voters": [{"voter_id": v, "public_key": k} for v, k in voter_keys.items()],
        "authorities": [
            {"authority_id": str(i), "public_key": str(pow(G, x, P))}
            for i, x in enumerate(xs, start=1)
        ],
    }
    public_dir = tmp_path / "data" / "public"
    return World(public_data, voter_keys, xs,
                 public_dir / "accepted_ballots.json", public_dir / "election.json")


@pytest.fixture
def world(tmp_path):
    return _make_world(tmp_path)


def _make_service(world, *, board_publisher=None, signature_verifier=verify_signature_stub, **kwargs):
    return VotingService(
        election_id=ELECTION_ID,
        group=GROUP,
        candidates=CANDIDATES,
        signature_verifier=signature_verifier,
        mod_exp=MOD_EXP,
        ballots_path=world.ballots_path,
        board_publisher=board_publisher,
        **kwargs,
    )


def make_ballot(service, world, voter_id, votes=(1, 0), *, signer=None, proof=None):
    """Cliente do eleitor: cifra (ElGamal exponencial) e assina a cédula.

    A prova, quando houver, entra nos bytes assinados: acrescentá-la depois
    invalidaria a assinatura.
    """
    h = service.election.joint_public_key
    ciphertexts = []
    for m in votes:
        r = 2 + secrets.randbelow(Q - 2)
        ciphertexts.append((pow(G, r, P), pow(G, m, P) * pow(h, r, P) % P))
    key = signer if signer is not None else world.voter_keys[voter_id]
    payload = ballot_signing_payload(ELECTION_ID, voter_id, ciphertexts, proof)
    ballot = {
        "election_id": ELECTION_ID,
        "voter_id": voter_id,
        "ciphertexts": [{"c1": c1, "c2": c2} for c1, c2 in ciphertexts],
        "signature": base64.b64encode(_sign(key, payload)).decode("ascii"),
    }
    if proof is not None:
        ballot["proof"] = proof
    return ballot


@pytest.fixture
def board():
    return mock.Mock(name="board_publisher")


@pytest.fixture
def service(world, board):
    svc = _make_service(world, board_publisher=board)
    svc.open_voting(world.public_data)
    return svc


def _published(board) -> list:
    return [call.args[0] for call in board.call_args_list]


# =============================================================================
# Fluxo completo
# =============================================================================
def test_full_flow_open_receive_close(world, board):
    svc = _make_service(world, board_publisher=board)
    assert svc.current_state() == "CADASTRO"
    assert svc.state is ElectionState.CADASTRO

    svc.open_voting(world.public_data)
    assert svc.current_state() == "VOTACAO_ABERTA"
    assert svc.state is ElectionState.VOTACAO_ABERTA
    assert svc.election.joint_public_key == world.joint_key

    receipts = []
    for voter_id, votes in (("eleitor-1", (1, 0)), ("eleitor-2", (0, 1)), ("eleitor-3", (1, 0))):
        receipt = svc.receive_ballot(make_ballot(svc, world, voter_id, votes))
        assert isinstance(receipt, Receipt)
        receipts.append(receipt)
    assert [r.index for r in receipts] == [0, 1, 2]

    svc.close_voting()
    assert svc.current_state() == "ENCERRADA"
    assert svc.state is ElectionState.ENCERRADA

    # Quadro: cada cédula aceita, uma vez, na ordem de aceitação.
    published = _published(board)
    assert published == list(svc.accepted_ballots)
    assert all(isinstance(b, AcceptedBallot) for b in published)
    assert [b.receipt for b in published] == [r.receipt for r in receipts]
    assert svc.pending_publications == ()

    data = json.loads(world.ballots_path.read_text())
    assert data["state"] == "ENCERRADA"
    assert [b["receipt"] for b in data["ballots"]] == [r.receipt for r in receipts]


def test_service_wraps_existing_election(world, board):
    election = Election(ELECTION_ID, GROUP, CANDIDATES, signature_verifier=verify_signature_stub,
                        mod_exp=MOD_EXP, ballots_path=world.ballots_path)
    svc = VotingService(election, board_publisher=board)
    assert svc.election is election
    svc.open_voting(world.public_data)
    receipt = svc.receive_ballot(make_ballot(svc, world, "eleitor-1"))
    assert election.has_voted("eleitor-1") and svc.has_voted("eleitor-1")
    assert board.call_args.args[0] is election.accepted_ballots[-1]
    assert board.call_args.args[0].receipt == receipt.receipt


def test_service_works_without_board(world):
    svc = _make_service(world)
    svc.open_voting(world.public_data)
    svc.receive_ballot(make_ballot(svc, world, "eleitor-1"))
    assert svc.pending_publications == ()
    assert svc.publish_pending() == 0


def test_current_state_serves_as_state_provider(world):
    svc = _make_service(world)
    provider = svc.current_state
    assert provider() == "CADASTRO"
    svc.open_voting(world.public_data)
    assert provider() == "VOTACAO_ABERTA"


def test_open_voting_forwards_election_path(world):
    svc = _make_service(world)
    world.election_path.parent.mkdir(parents=True, exist_ok=True)
    world.election_path.write_text(json.dumps({
        "group": {"p": str(P), "q": str(Q), "g": str(G)},
        "joint_public_key": str(pow(G, 12345, P)),  # diverge da chave real
        "frozen": True,
    }))
    with pytest.raises(VotingPreconditionError, match="joint_public_key"):
        svc.open_voting(world.public_data, election_path=world.election_path)
    assert svc.current_state() == "CADASTRO"

    published = json.loads(world.election_path.read_text())
    published["joint_public_key"] = str(world.joint_key)
    world.election_path.write_text(json.dumps(published))
    svc.open_voting(world.public_data, election_path=world.election_path)
    assert svc.current_state() == "VOTACAO_ABERTA"


# =============================================================================
# Construção e verificador padrão
# =============================================================================
def _module(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    return module


def _build_with_default_verifier(world, modules):
    with mock.patch.dict(sys.modules, modules):
        return VotingService(election_id=ELECTION_ID, group=GROUP, candidates=CANDIDATES,
                             mod_exp=MOD_EXP, ballots_path=world.ballots_path)


def _vote_once(svc, world):
    svc.open_voting(world.public_data)
    svc.receive_ballot(make_ballot(svc, world, "eleitor-1"))


def test_default_verifier_prefers_server_validation(world):
    validation = mock.Mock(side_effect=verify_signature_stub)
    crypto = mock.Mock(return_value=False)
    svc = _build_with_default_verifier(world, {
        "src.server.validation": _module("src.server.validation", verify_signature=validation),
        "src.crypto.signatures": _module("src.crypto.signatures", verify_signature=crypto),
    })
    _vote_once(svc, world)
    validation.assert_called_once()
    crypto.assert_not_called()


@pytest.mark.parametrize("validation_module", [
    None,                                            # módulo ausente na branch
    _module("src.server.validation"),                # módulo sem verify_signature
], ids=["ausente", "sem-funcao"])
def test_default_verifier_falls_back_to_crypto_signatures(world, validation_module):
    crypto = mock.Mock(side_effect=verify_signature_stub)
    svc = _build_with_default_verifier(world, {
        "src.server.validation": validation_module,
        "src.crypto.signatures": _module("src.crypto.signatures", verify_signature=crypto),
    })
    _vote_once(svc, world)
    crypto.assert_called_once()


def test_missing_verifier_requires_explicit_injection(world):
    with pytest.raises(RuntimeError, match="signature_verifier"):
        _build_with_default_verifier(world, {
            "src.server.validation": None,
            "src.crypto.signatures": None,
        })


def test_explicit_verifier_wins_over_defaults(world):
    explicit = mock.Mock(side_effect=verify_signature_stub)
    default = mock.Mock(return_value=False)
    with mock.patch.dict(sys.modules, {
        "src.server.validation": _module("src.server.validation", verify_signature=default),
    }):
        svc = _make_service(world, signature_verifier=explicit)
    _vote_once(svc, world)
    explicit.assert_called_once()
    default.assert_not_called()


def test_constructor_rejects_ambiguous_or_invalid_configuration(world):
    election = Election(ELECTION_ID, GROUP, CANDIDATES, signature_verifier=verify_signature_stub,
                        mod_exp=MOD_EXP, ballots_path=world.ballots_path)
    with pytest.raises(ValueError):
        VotingService(election, election_id=ELECTION_ID)
    with pytest.raises(ValueError):
        VotingService(election, require_proof=True)
    with pytest.raises(TypeError):
        VotingService(object())
    with pytest.raises(TypeError):
        VotingService(election, board_publisher="não é função")
    with pytest.raises(TypeError):
        VotingService(group=GROUP, candidates=CANDIDATES, signature_verifier=verify_signature_stub)


def test_board_requires_election_without_unpublished_ballots(world, board):
    election = Election(ELECTION_ID, GROUP, CANDIDATES, signature_verifier=verify_signature_stub,
                        mod_exp=MOD_EXP, ballots_path=world.ballots_path)
    plain = VotingService(election)
    plain.open_voting(world.public_data)
    plain.receive_ballot(make_ballot(plain, world, "eleitor-1"))
    with pytest.raises(ValueError, match="não foram publicadas"):
        VotingService(election, board_publisher=board)


# =============================================================================
# Quadro público: só cédulas aceitas
# =============================================================================
@pytest.mark.parametrize(
    "build, expected",
    [
        (lambda s, w: make_ballot(s, w, "intruso", signer=INTRUDER_KEY), IneligibleVoterError),
        (lambda s, w: make_ballot(s, w, "eleitor-1", signer=w.voter_keys["eleitor-2"]),
         InvalidSignatureError),
        (lambda s, w: {**make_ballot(s, w, "eleitor-1"), "extra": "contrabando"}, InvalidBallotError),
        (lambda s, w: {**make_ballot(s, w, "eleitor-1"), "voter_id": "../evil"}, InvalidBallotError),
    ],
    ids=["inelegivel", "assinatura-invalida", "campo-extra", "path-traversal"],
)
def test_board_not_called_for_rejected_ballot(service, world, board, build, expected):
    with pytest.raises(expected):
        service.receive_ballot(build(service, world))
    board.assert_not_called()
    assert service.accepted_ballots == ()
    assert service.pending_publications == ()


def test_board_not_called_for_duplicate_vote(service, world, board):
    first = make_ballot(service, world, "eleitor-1", (1, 0))
    service.receive_ballot(first)
    assert board.call_count == 1

    for second in (make_ballot(service, world, "eleitor-1", (0, 1)), first):
        with pytest.raises(DuplicateVoteError):
            service.receive_ballot(second)
    assert board.call_count == 1
    assert _published(board) == [service.accepted_ballots[0]]


def test_board_not_called_before_open_or_after_close(world, board):
    svc = _make_service(world, board_publisher=board)
    static = {
        "election_id": ELECTION_ID,
        "voter_id": "eleitor-1",
        "ciphertexts": [{"c1": 4, "c2": 4}, {"c1": 16, "c2": 16}],
        "signature": "AAAA",
    }
    with pytest.raises(VotingClosedError):
        svc.receive_ballot(static)

    svc.open_voting(world.public_data)
    late = make_ballot(svc, world, "eleitor-1")
    svc.close_voting()
    with pytest.raises(VotingClosedError):
        svc.receive_ballot(late)
    board.assert_not_called()


def test_board_receives_immutable_accepted_ballot(service, world, board):
    receipt = service.receive_ballot(make_ballot(service, world, "eleitor-1"))
    record = board.call_args.args[0]
    assert record is service.accepted_ballots[-1]
    assert (record.index, record.voter_id, record.receipt) == (receipt.index, receipt.voter_id,
                                                              receipt.receipt)
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.voter_id = "outro"


# =============================================================================
# Falha do quadro público
# =============================================================================
def test_board_failure_keeps_vote_and_retries_in_order(world):
    board = mock.Mock(side_effect=[OSError("quadro fora do ar"), None, None])
    svc = _make_service(world, board_publisher=board)
    svc.open_voting(world.public_data)

    with pytest.raises(BoardPublicationError) as info:
        svc.receive_ballot(make_ballot(svc, world, "eleitor-1"))
    # O voto conta: a eleição aceitou e persistiu; o recibo vem na exceção.
    assert info.value.receipt is not None and info.value.receipt.index == 0
    assert info.value.ballot is svc.accepted_ballots[0]
    assert svc.has_voted("eleitor-1")
    assert svc.pending_publications == (svc.accepted_ballots[0],)

    # Próximo voto: a pendência é publicada antes da cédula nova.
    svc.receive_ballot(make_ballot(svc, world, "eleitor-2"))
    first, second = svc.accepted_ballots
    assert _published(board) == [first, first, second]
    assert svc.pending_publications == ()


def test_unpublishable_pending_blocks_new_ballots(world):
    board = mock.Mock(side_effect=OSError("quadro fora do ar"))
    svc = _make_service(world, board_publisher=board)
    svc.open_voting(world.public_data)

    with pytest.raises(BoardPublicationError):
        svc.receive_ballot(make_ballot(svc, world, "eleitor-1"))
    with pytest.raises(BoardPublicationError) as info:
        svc.receive_ballot(make_ballot(svc, world, "eleitor-2"))
    # Falhou ao publicar a pendência: a cédula nova nem foi processada.
    assert info.value.receipt is None
    assert info.value.ballot.voter_id == "eleitor-1"
    assert not svc.has_voted("eleitor-2")

    # O encerramento não depende do quadro; as pendências seguem na fila.
    svc.close_voting()
    assert svc.current_state() == "ENCERRADA"
    board.side_effect = None
    assert svc.publish_pending() == 1
    assert svc.pending_publications == ()
    assert _published(board)[-1] is svc.accepted_ballots[0]


def test_board_failure_is_not_a_vote_rejection():
    assert not issubclass(BoardPublicationError, states_mod.ElectionError)
    assert issubclass(BoardPublicationError, RuntimeError)


# =============================================================================
# Propagação das exceções
# =============================================================================
@pytest.mark.parametrize("name, module", [
    ("VotingClosedError", "election"),
    ("IneligibleVoterError", "election"),
    ("DuplicateVoteError", "election"),
    ("InvalidBallotError", "election"),
    ("InvalidSignatureError", "election"),
    ("InvalidProofError", "election"),
    ("VotingPreconditionError", "states"),
    ("InvalidStateTransitionError", "states"),
])
def test_exceptions_are_reexported_unchanged(name, module):
    source = election_mod if module == "election" else states_mod
    assert getattr(voting_mod, name) is getattr(source, name)
    assert name in voting_mod.__all__


def test_open_voting_precondition_errors_propagate(tmp_path):
    for world, match in (
        (_make_world(tmp_path / "a", frozen=False), "congelado"),
        (_make_world(tmp_path / "b", n_authorities=2), "autoridades"),
    ):
        svc = _make_service(world)
        with pytest.raises(VotingPreconditionError, match=match):
            svc.open_voting(world.public_data)
        assert svc.current_state() == "CADASTRO"
        assert not world.ballots_path.exists()


def test_invalid_transitions_propagate(world):
    svc = _make_service(world)
    with pytest.raises(InvalidStateTransitionError):
        svc.close_voting()  # CADASTRO -> ENCERRADA
    svc.open_voting(world.public_data)
    with pytest.raises(InvalidStateTransitionError):
        svc.open_voting(world.public_data)  # abrir duas vezes
    svc.close_voting()
    with pytest.raises(InvalidStateTransitionError):
        svc.close_voting()  # encerrar duas vezes
    with pytest.raises(InvalidStateTransitionError):
        svc.open_voting(world.public_data)  # reabrir
    assert svc.current_state() == "ENCERRADA"


@pytest.mark.parametrize("proof_verifier, proof, require_proof, match", [
    (None, {"scheme": "qualquer"}, False, "verificador"),                  # sem verificador
    (mock.Mock(return_value=False), {"scheme": "qualquer"}, False, "inválida"),  # prova recusada
    (mock.Mock(return_value=True), None, True, "exige"),                   # prova obrigatória ausente
], ids=["sem-verificador", "prova-recusada", "prova-ausente"])
def test_proof_errors_propagate(world, board, proof_verifier, proof, require_proof, match):
    svc = _make_service(world, board_publisher=board,
                        proof_verifier=proof_verifier, require_proof=require_proof)
    svc.open_voting(world.public_data)
    # A prova é assinada junto com a cédula: assim a assinatura é válida e a
    # rejeição vem da checagem da prova.
    ballot = make_ballot(svc, world, "eleitor-1", proof=proof)
    with pytest.raises(InvalidProofError, match=match):
        svc.receive_ballot(ballot)
    board.assert_not_called()
    assert not svc.has_voted("eleitor-1")


def test_proof_added_after_signing_is_invalid_signature(world, board):
    svc = _make_service(world, board_publisher=board)
    svc.open_voting(world.public_data)
    ballot = make_ballot(svc, world, "eleitor-1")
    ballot["proof"] = {"scheme": "qualquer"}  # adulteração após a assinatura
    with pytest.raises(InvalidSignatureError):
        svc.receive_ballot(ballot)
    board.assert_not_called()


def test_rejection_errors_are_vote_rejections():
    for exc in (IneligibleVoterError, DuplicateVoteError, InvalidBallotError,
                InvalidSignatureError, InvalidProofError):
        assert issubclass(exc, voting_mod.VoteRejectedError)
    assert issubclass(VotingClosedError, voting_mod.ElectionStateError)