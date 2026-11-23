"""Testes da camada de serviço de votação (``src.server.voting``).

``VotingService`` só orquestra: as regras da eleição já têm testes em
``test_election_voting.py``. Aqui verificamos o fluxo, a integração com o
quadro público (um mock que registra as chamadas e o
``src.bulletin_board.board.BulletinBoard`` REAL, via ``board_publisher_for``)
e a propagação das exceções.

Módulos reais, sem stubs: nada é substituído em ``sys.modules``. O cadastro
é o dicionário no formato de ``export_public_data()``, com chaves RSA reais;
as cédulas são envelopes de ``src.crypto.ballots`` cifrados com
``encrypt_bit`` e assinados com ``sign_ballot``.
"""

import dataclasses
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

from src.crypto.ballots import BallotFormatError, sign_ballot  # noqa: E402
from src.crypto.bit_proof import prove_bit  # noqa: E402
from src.crypto.elgamal import encrypt_bit  # noqa: E402
from src.crypto.keys import public_key_to_pem  # noqa: E402
from src.crypto.signatures import generate_signing_key  # noqa: E402
from src.election.election import AcceptedBallot, Election, compute_receipt  # noqa: E402
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
    board_publisher_for,
)

election_mod = sys.modules["src.election.election"]
states_mod = sys.modules["src.election.states"]
voting_mod = sys.modules["src.server.voting"]


# =============================================================================
# Grupo e chaves reais
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

# RSA de 2048 bits é lento: um conjunto para o módulo inteiro.
VOTER_KEYS = {f"eleitor-{i}": generate_signing_key(2048) for i in (1, 2, 3)}
INTRUDER_KEY = generate_signing_key(2048)

_NO_PROOF_FIELD = (
    "O envelope de src.crypto.ballots não tem campo para a prova 0/1: sign_ballot "
    "recusa a cédula com prova (BallotFormatError). Quando src.crypto.bit_proof "
    "entrar no formato, este teste passa a executar e o xfail estrito obriga a "
    "atualizá-lo."
)


# =============================================================================
# Ambiente
# =============================================================================
@dataclasses.dataclass
class World:
    public_data: dict
    voter_keys: dict  # voter_id -> chave privada RSA (lado do eleitor)
    authority_xs: list
    ballots_path: Path
    election_path: Path

    @property
    def joint_key(self) -> int:
        return pow(G, sum(self.authority_xs), P)


def _make_world(tmp_path, *, frozen=True, n_authorities=3) -> World:
    voter_keys = dict(VOTER_KEYS)
    xs = [2 + secrets.randbelow(Q - 2) for _ in range(n_authorities)]
    public_data = {
        "schema_version": 1,
        "election_id": ELECTION_ID,
        "frozen": frozen,
        "voters": [{"voter_id": v, "public_key": public_key_to_pem(k.public_key())}
                   for v, k in voter_keys.items()],
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


def _make_service(world, *, board_publisher=None, **kwargs):
    return VotingService(
        election_id=ELECTION_ID,
        group=GROUP,
        candidates=CANDIDATES,
        ballots_path=world.ballots_path,
        board_publisher=board_publisher,
        **kwargs,
    )


def _ballot_body(voter_id, ciphertexts) -> dict:
    return {
        "schema_version": 1,
        "election_id": ELECTION_ID,
        "voter_id": voter_id,
        "ciphertexts": [{"candidate_id": cid, "c1": str(c1), "c2": str(c2)}
                        for cid, (c1, c2) in zip(CANDIDATES, ciphertexts)],
    }


def make_ballot(service, world, voter_id, votes=(1, 0), *, signer=None, with_proof=False):
    """Cliente do eleitor: cifra (encrypt_bit) e assina o envelope (sign_ballot).

    ``with_proof=True`` tenta incluir provas 0/1 reais na cédula: hoje
    ``sign_ballot`` recusa (BallotFormatError), pois o formato não tem o campo.
    """
    h = service.election.joint_public_key
    ciphertexts, proofs = [], []
    for m in votes:
        ciphertext, r = encrypt_bit(m, h, GROUP)
        ciphertexts.append((ciphertext.a, ciphertext.b))
        if with_proof:
            proof = prove_bit(ciphertext, h, r, m, GROUP)
            proofs.append({k: str(v) for k, v in dataclasses.asdict(proof).items()})
    key = signer if signer is not None else world.voter_keys[voter_id]
    body = _ballot_body(voter_id, ciphertexts)
    if with_proof:
        body["proof"] = proofs
    return sign_ballot(body, key)


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


def test_full_flow_with_the_real_bulletin_board(world):
    """Formato único ponta a ponta: o quadro real reverifica e grava cada cédula."""
    pytest.importorskip("fcntl", reason="src.bulletin_board.board usa fcntl (Linux, macOS ou WSL)")
    from src.bulletin_board.board import BulletinBoard

    voters = {v["voter_id"]: v["public_key"] for v in world.public_data["voters"]}
    board = BulletinBoard.create(_board_path(world), election_id=ELECTION_ID,
                                 candidate_ids=CANDIDATES, voter_public_keys=voters)
    svc = _make_service(world, board_publisher=board_publisher_for(board))
    svc.open_voting(world.public_data)

    sent = {}
    for voter_id, votes in (("eleitor-1", (1, 0)), ("eleitor-2", (0, 1)), ("eleitor-3", (1, 0))):
        sent[voter_id] = make_ballot(svc, world, voter_id, votes)
        svc.receive_ballot(sent[voter_id])
    with pytest.raises(DuplicateVoteError):
        svc.receive_ballot(make_ballot(svc, world, "eleitor-2", (1, 0)))

    records = board.records()  # releitura verificada pelo próprio quadro
    assert [r["index"] for r in records] == [0, 1, 2]
    assert [r["ballot"] for r in records] == [e["ballot"] for e in sent.values()]
    assert [r["signature"] for r in records] == [e["signature"] for e in sent.values()]
    # O recibo da eleição é recalculável a partir do registro público.
    assert [compute_receipt(r["ballot"], r["signature"]) for r in records] == [
        b.receipt for b in svc.accepted_ballots
    ]
    assert svc.pending_publications == ()


@pytest.mark.security
def test_ciphertext_copied_from_other_voter_never_reaches_the_board(world):
    """c1 repetido é rejeitado no RECEBIMENTO (pela Election), antes do quadro.

    Importa para a conferência das autoridades: elas recusam um quadro com
    ``c1`` repetido (a cópia faria o voto copiado contar duas vezes). Se o
    servidor aceitasse a cópia, um eleitor conivente bloquearia a apuração;
    como a rejeição acontece aqui, o quadro real nunca fica nesse estado.
    """
    pytest.importorskip("fcntl", reason="src.bulletin_board.board usa fcntl (Linux, macOS ou WSL)")
    from src.bulletin_board.board import BulletinBoard

    voters = {v["voter_id"]: v["public_key"] for v in world.public_data["voters"]}
    board = BulletinBoard.create(_board_path(world), election_id=ELECTION_ID,
                                 candidate_ids=CANDIDATES, voter_public_keys=voters)
    svc = _make_service(world, board_publisher=board_publisher_for(board))
    svc.open_voting(world.public_data)
    original = make_ballot(svc, world, "eleitor-1", (1, 0))
    svc.receive_ballot(original)
    board_before = _board_path(world).read_bytes()

    # eleitor-2 assina com a PRÓPRIA chave as cifras copiadas do eleitor-1.
    pairs = [(int(c["c1"]), int(c["c2"])) for c in original["ballot"]["ciphertexts"]]
    copied = sign_ballot(_ballot_body("eleitor-2", pairs), world.voter_keys["eleitor-2"])
    with pytest.raises(InvalidBallotError, match="já usado em outra cédula"):
        svc.receive_ballot(copied)

    assert not svc.has_voted("eleitor-2")
    assert _board_path(world).read_bytes() == board_before
    assert [r["ballot"]["voter_id"] for r in board.records()] == ["eleitor-1"]
    assert svc.pending_publications == ()


def _board_path(world) -> Path:
    world.ballots_path.parent.mkdir(parents=True, exist_ok=True)
    return world.ballots_path.parent / "bulletin_board.jsonl"


def test_board_publisher_for_requires_append():
    with pytest.raises(TypeError):
        board_publisher_for(object())


def test_service_wraps_existing_election(world, board):
    election = Election(ELECTION_ID, GROUP, CANDIDATES, ballots_path=world.ballots_path)
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
# Construção e verificação de assinatura
#
# Antes, o serviço procurava um verify_signature "padrão" em
# src.server.validation e src.crypto.signatures (testado com módulos falsos
# em sys.modules) ou aceitava um verificador injetado. No formato único, a
# assinatura é SEMPRE verificada pela Election com
# src.crypto.ballots.verify_signed_ballot: não há descoberta nem injeção.
# =============================================================================
def test_service_always_verifies_with_crypto_ballots(world, board, monkeypatch):
    # Substitui "verificador padrão preferido / fallback": o verificador é
    # sempre o real; o mock só conta as chamadas.
    spy = mock.Mock(wraps=election_mod.verify_signed_ballot)
    monkeypatch.setattr(election_mod, "verify_signed_ballot", spy)
    svc = _make_service(world, board_publisher=board)
    svc.open_voting(world.public_data)
    svc.receive_ballot(make_ballot(svc, world, "eleitor-1"))
    spy.assert_called_once()
    with pytest.raises(InvalidSignatureError):
        svc.receive_ballot(make_ballot(svc, world, "eleitor-2", signer=INTRUDER_KEY))
    assert spy.call_count == 2
    assert board.call_count == 1


def test_signature_verifier_cannot_be_injected_or_disabled(world):
    # Substitui "verificador ausente exige injeção" e "injetado vence o
    # padrão": não existe parâmetro para trocar ou desligar a verificação.
    with pytest.raises(TypeError):
        _make_service(world, signature_verifier=lambda *args: True)
    with pytest.raises(TypeError):
        Election(ELECTION_ID, GROUP, CANDIDATES, signature_verifier=lambda *args: True,
                 ballots_path=world.ballots_path)
    assert not hasattr(voting_mod, "load_default_signature_verifier")


def test_constructor_rejects_ambiguous_or_invalid_configuration(world):
    election = Election(ELECTION_ID, GROUP, CANDIDATES, ballots_path=world.ballots_path)
    with pytest.raises(ValueError):
        VotingService(election, election_id=ELECTION_ID)
    with pytest.raises(TypeError):
        VotingService(object())
    with pytest.raises(TypeError):
        VotingService(election, board_publisher="não é função")
    with pytest.raises(TypeError):
        VotingService(group=GROUP, candidates=CANDIDATES)  # falta election_id


def test_board_requires_election_without_unpublished_ballots(world, board):
    election = Election(ELECTION_ID, GROUP, CANDIDATES, ballots_path=world.ballots_path)
    plain = VotingService(election)
    plain.open_voting(world.public_data)
    plain.receive_ballot(make_ballot(plain, world, "eleitor-1"))
    with pytest.raises(ValueError, match="não foram publicadas"):
        VotingService(election, board_publisher=board)


# =============================================================================
# Quadro público: só cédulas aceitas
# =============================================================================
def _set_voter(envelope, voter_id):
    envelope["ballot"]["voter_id"] = voter_id
    return envelope


@pytest.mark.security
@pytest.mark.parametrize(
    "build, expected",
    [
        (lambda s, w: make_ballot(s, w, "intruso", signer=INTRUDER_KEY), IneligibleVoterError),
        (lambda s, w: make_ballot(s, w, "eleitor-1", signer=w.voter_keys["eleitor-2"]),
         InvalidSignatureError),
        (lambda s, w: {**make_ballot(s, w, "eleitor-1"), "extra": "contrabando"}, InvalidBallotError),
        (lambda s, w: _set_voter(make_ballot(s, w, "eleitor-1"), "../evil"), InvalidBallotError),
    ],
    ids=["inelegivel", "assinatura-invalida", "campo-extra", "path-traversal"],
)
def test_board_not_called_for_rejected_ballot(service, world, board, build, expected):
    with pytest.raises(expected):
        service.receive_ballot(build(service, world))
    board.assert_not_called()
    assert service.accepted_ballots == ()
    assert service.pending_publications == ()


@pytest.mark.security
def test_board_not_called_for_duplicate_vote(service, world, board):
    first = make_ballot(service, world, "eleitor-1", (1, 0))
    service.receive_ballot(first)
    assert board.call_count == 1

    for second in (make_ballot(service, world, "eleitor-1", (0, 1)), first):
        with pytest.raises(DuplicateVoteError):
            service.receive_ballot(second)
    assert board.call_count == 1
    assert _published(board) == [service.accepted_ballots[0]]


@pytest.mark.security
def test_board_not_called_before_open_or_after_close(world, board):
    svc = _make_service(world, board_publisher=board)
    static = {"ballot": _ballot_body("eleitor-1", [(4, 4), (16, 16)]), "signature": "AAAA"}
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


@pytest.mark.parametrize("where", ["cedula", "envelope"])
def test_proof_field_rejection_propagates(world, board, where):
    # Antes: erros de prova (sem verificador, recusada, ausente) propagavam
    # como InvalidProofError. Hoje a prova não tem campo no formato: um campo
    # "proof" é recusado pela Election e a rejeição propaga sem tocar o quadro.
    svc = _make_service(world, board_publisher=board)
    svc.open_voting(world.public_data)
    ballot = make_ballot(svc, world, "eleitor-1")
    (ballot["ballot"] if where == "cedula" else ballot)["proof"] = {"scheme": "qualquer"}
    with pytest.raises(InvalidBallotError, match="desconhecidos"):
        svc.receive_ballot(ballot)
    board.assert_not_called()
    assert not svc.has_voted("eleitor-1")


@pytest.mark.xfail(strict=True, raises=BallotFormatError, reason=_NO_PROOF_FIELD)
@pytest.mark.parametrize("case", ["sem-verificador", "prova-recusada", "prova-ausente"])
def test_proof_errors_propagate(world, board, case):
    svc = _make_service(world, board_publisher=board)
    svc.open_voting(world.public_data)
    ballot = make_ballot(svc, world, "eleitor-1", with_proof=True)
    with pytest.raises(InvalidProofError):
        svc.receive_ballot(ballot)
    board.assert_not_called()


def test_proof_added_after_signing_is_rejected(world, board):
    svc = _make_service(world, board_publisher=board)
    svc.open_voting(world.public_data)
    ballot = make_ballot(svc, world, "eleitor-1")
    ballot["ballot"]["proof"] = {"scheme": "qualquer"}  # adulteração após a assinatura
    # Fora do formato assinado: recusada antes mesmo de verificar a assinatura.
    with pytest.raises(InvalidBallotError, match="desconhecidos"):
        svc.receive_ballot(ballot)
    board.assert_not_called()


def test_ciphertext_altered_after_signing_is_invalid_signature(world, board):
    svc = _make_service(world, board_publisher=board)
    svc.open_voting(world.public_data)
    ballot = make_ballot(svc, world, "eleitor-1")
    target = ballot["ballot"]["ciphertexts"][0]
    target["c2"] = str(int(target["c2"]) * G % P)  # m -> m+1, sem refazer a assinatura
    with pytest.raises(InvalidSignatureError):
        svc.receive_ballot(ballot)
    board.assert_not_called()


def test_rejection_errors_are_vote_rejections():
    for exc in (IneligibleVoterError, DuplicateVoteError, InvalidBallotError,
                InvalidSignatureError, InvalidProofError):
        assert issubclass(exc, voting_mod.VoteRejectedError)
    assert issubclass(VotingClosedError, voting_mod.ElectionStateError)