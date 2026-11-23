"""Testes da máquina de estados, elegibilidade e validação das cédulas.

Independência de branch
-----------------------
- ``src.crypto.group``: se não existir, ``mod_exp`` é simulado com
  ``unittest.mock`` (apenas aqui). Em qualquer caso, é injetado em
  ``Election(mod_exp=...)``.
- ``src.authorities.authority``: se não existir, um stub mínimo oferece
  ``MIN_AUTHORITIES``, ``GroupParams``, ``JointKeyError``,
  ``compute_joint_public_key`` e ``publish_joint_public_key``.
- ``src.server.registration``: se não existir, um substituto mínimo com o
  mesmo formato de ``export_public_data()``.
- Assinatura do eleitor: verificador injetado e determinístico. Com a
  biblioteca ``cryptography``, é RSA PKCS#1 v1.5 + SHA-256 de verdade;
  sem ela, um stub baseado em SHA-256. Se o módulo de crypto real usar outro
  esquema, ajuste apenas ``_sign`` e ``verify_signature_stub``.
- Prova ZKP: verificador injetado e determinístico (``zkp_verifier_stub``).

Etapas oficiais (README, ``src.election.states``)::

    CONFIGURACAO -> CADASTRO -> VOTACAO_ABERTA -> ENCERRADA -> APURACAO -> AUDITADA

``pow`` nativo aparece só aqui: para simular o cliente do eleitor (cifrar),
as autoridades (gerar h_i) e como oráculo independente.
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
# Independência de branch: stubs só quando o módulo real não existe
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


# --- src.crypto.group --------------------------------------------------------
try:
    from src.crypto.group import mod_exp as MOD_EXP
except ImportError:
    MOD_EXP = mock.Mock(name="mod_exp", side_effect=lambda b, e, m: pow(b, e, m))
    if "src.crypto.group" in sys.modules:
        sys.modules["src.crypto.group"].mod_exp = MOD_EXP
    else:
        _install_stub("src.crypto.group", mod_exp=MOD_EXP)
# Pelo tipo, e não por quem instalou: outro arquivo de testes pode ter
# instalado o mesmo mock antes deste.
CRYPTO_GROUP_STUBBED = isinstance(MOD_EXP, mock.Mock)

# --- src.authorities.authority ----------------------------------------------
try:
    from src.authorities.authority import (
        MIN_AUTHORITIES,
        compute_joint_public_key,
        publish_joint_public_key,
    )

    AUTHORITY_STUBBED = False
except ImportError:
    AUTHORITY_STUBBED = True
    MIN_AUTHORITIES = 3

    @runtime_checkable
    class _StubGroupParams(Protocol):
        p: int
        q: int
        g: int

    class _StubJointKeyError(ValueError):
        pass

    def compute_joint_public_key(public_data, group, *, min_authorities=3):
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

    def publish_joint_public_key(public_data, group, election_path, *, min_authorities=3):
        h = compute_joint_public_key(public_data, group, min_authorities=min_authorities)
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
        MIN_AUTHORITIES=MIN_AUTHORITIES,
        GroupParams=_StubGroupParams,
        JointKeyError=_StubJointKeyError,
        compute_joint_public_key=compute_joint_public_key,
        publish_joint_public_key=publish_joint_public_key,
    )

# --- módulos testados --------------------------------------------------------
from src.election.election import (  # noqa: E402
    AcceptedBallot,
    DuplicateVoteError,
    Election,
    IneligibleVoterError,
    InvalidBallotError,
    InvalidProofError,
    InvalidSignatureError,
    Receipt,
    VotingClosedError,
    ballot_signing_payload,
    compute_receipt,
)
from src.election.states import (  # noqa: E402
    NEXT_STATE,
    ElectionState,
    InvalidStateTransitionError,
    VotingPreconditionError,
)

election_mod = sys.modules["src.election.election"]
states_mod = sys.modules["src.election.states"]
election_pkg = importlib.import_module("src.election")

# --- src.server.registration -------------------------------------------------
try:
    from src.server.registration import Registration, RegistrationClosedError

    REGISTRATION_STUBBED = False
except ImportError:
    REGISTRATION_STUBBED = True

    class RegistrationClosedError(ValueError):
        pass

    class Registration:
        """Substituto mínimo, com o formato de export_public_data() combinado."""

        def __init__(self, election_id, *, p, q, state_provider):
            self._election_id = election_id
            self._state_provider = state_provider
            self._frozen = False
            self._voters = {}
            self._authorities = {}

        def _require_open(self):
            if self._frozen or self._state_provider() != "CADASTRO":
                raise RegistrationClosedError("cadastro fechado")

        def register_voter(self, voter_id, public_key):
            self._require_open()
            if voter_id in self._voters:
                raise ValueError("eleitor repetido")
            self._voters[voter_id] = public_key

        def register_authority(self, authority_id, public_key):
            self._require_open()
            if authority_id in self._authorities:
                raise ValueError("autoridade repetida")
            self._authorities[authority_id] = public_key

        def freeze(self):
            self._frozen = True

        def export_public_data(self):
            return {
                "schema_version": 1,
                "election_id": self._election_id,
                "frozen": self._frozen,
                "voters": [
                    {"voter_id": v, "public_key": k} for v, k in self._voters.items()
                ],
                "authorities": [
                    {"authority_id": a, "public_key": str(h)}
                    for a, h in self._authorities.items()
                ],
            }

# --- cryptography (opcional) -------------------------------------------------
try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - depende do ambiente
    HAVE_CRYPTOGRAPHY = False


# =============================================================================
# Grupo e constantes
# =============================================================================
# RFC 3526, grupo 14 (MODP 2048 bits): p primo seguro, q = (p-1)/2 primo e,
# como p ≡ 7 (mod 8), g = 2 é resíduo quadrático e gera o subgrupo de ordem q.
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


# =============================================================================
# Assinatura do eleitor (cliente) e verificador determinístico
# =============================================================================
@dataclasses.dataclass(frozen=True)
class VoterKey:
    public_key: str
    private: object = dataclasses.field(default=None, repr=False)


def _new_voter_key(i: int) -> VoterKey:
    if HAVE_CRYPTOGRAPHY:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")
        return VoterKey(pem, private)
    # Sem cryptography, o Registration real também não importa: o substituto
    # aceita este texto como chave pública.
    pem = f"-----BEGIN PUBLIC KEY-----\nSTUB-{i}-{secrets.token_hex(8)}\n-----END PUBLIC KEY-----\n"
    return VoterKey(pem)


def _sign(key: VoterKey, payload: bytes) -> bytes:
    """Cliente do eleitor: único ponto que conhece o esquema de assinatura."""
    if HAVE_CRYPTOGRAPHY:
        return key.private.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    return hashlib.sha256(key.public_key.encode("ascii") + payload).digest()


def verify_signature_stub(public_key: str, message: bytes, signature: bytes) -> bool:
    """Verificador determinístico injetado em Election(signature_verifier=...)."""
    if HAVE_CRYPTOGRAPHY:
        key = serialization.load_pem_public_key(public_key.encode("ascii"))
        try:
            key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
            return True
        except InvalidSignature:
            return False
    return signature == hashlib.sha256(public_key.encode("ascii") + message).digest()


# =============================================================================
# Prova ZKP: stub determinístico, amarrado às cifras
# =============================================================================
def _ciphertexts_digest(ciphertexts) -> str:
    canonical = json.dumps([[str(c1), str(c2)] for c1, c2 in ciphertexts])
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def make_proof(ciphertexts) -> dict:
    return {"scheme": "stub-zkp", "digest": _ciphertexts_digest(ciphertexts)}


def zkp_verifier_stub(proof, ciphertexts, group, joint_public_key) -> bool:
    return bool(
        type(proof) is dict
        and proof.get("scheme") == "stub-zkp"
        and proof.get("digest") == _ciphertexts_digest(ciphertexts)
    )


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
    proof_verifier: object
    randomness: list = dataclasses.field(default_factory=list)

    def encrypt(self, m: int) -> tuple:
        """Cliente do eleitor: (c1, c2) = (g^r, g^m · h^r mod p)."""
        r = 2 + secrets.randbelow(Q - 2)
        self.randomness.append(r)
        h = self.election.joint_public_key
        return (pow(G, r, P), pow(G, m, P) * pow(h, r, P) % P)

    def signed(self, voter_id, ciphertexts, *, key=None, proof=None, election_id=ELECTION_ID):
        key = key if key is not None else self.voter_keys[voter_id]
        payload = ballot_signing_payload(election_id, voter_id, ciphertexts, proof)
        ballot = {
            "election_id": election_id,
            "voter_id": voter_id,
            "ciphertexts": [{"c1": c1, "c2": c2} for c1, c2 in ciphertexts],
            "signature": base64.b64encode(_sign(key, payload)).decode("ascii"),
        }
        if proof is not None:
            ballot["proof"] = proof
        return ballot

    def ballot(self, voter_id, votes=(1, 0), *, key=None, with_proof=False):
        ciphertexts = [self.encrypt(m) for m in votes]
        proof = make_proof(ciphertexts) if with_proof else None
        return self.signed(voter_id, ciphertexts, key=key, proof=proof)


@pytest.fixture(scope="module")
def key_pool():
    # RSA de 2048 bits é lento; o mesmo conjunto serve a todos os testes.
    return [_new_voter_key(i) for i in range(4)]


def _build(
    tmp_path,
    key_pool,
    *,
    n_voters=3,
    n_authorities=3,
    freeze=True,
    publish=True,
    open_voting=True,
    signature_verifier=None,
    proof_verifier=None,
    require_proof=False,
) -> Env:
    election_path = tmp_path / "data" / "public" / "election.json"
    ballots_path = tmp_path / "data" / "public" / "accepted_ballots.json"
    if signature_verifier is None:
        signature_verifier = mock.Mock(side_effect=verify_signature_stub)

    election = Election(
        ELECTION_ID,
        GROUP,
        CANDIDATES,
        signature_verifier=signature_verifier,
        proof_verifier=proof_verifier,
        require_proof=require_proof,
        mod_exp=MOD_EXP,
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
        election_path, ballots_path, signature_verifier, proof_verifier,
    )
    if open_voting:
        election.open_voting(public_data, election_path=election_path)
    return env


@pytest.fixture
def env(tmp_path, key_pool):
    return _build(tmp_path, key_pool)


def _ballots_file(env) -> dict:
    return json.loads(env.ballots_path.read_text(encoding="utf-8"))


def _pairs(ballot) -> list:
    return [(c["c1"], c["c2"]) for c in ballot["ciphertexts"]]


# =============================================================================
# Configuração
# =============================================================================
def test_group_parameters_are_rfc3526_2048():
    assert P.bit_length() == 2048
    assert Q.bit_length() >= 224
    assert P == 2 * Q + 1
    assert pow(G, Q, P) == 1 and G != 1
    assert pow(NON_RESIDUE, Q, P) == P - 1


def test_signature_verifier_is_mandatory(tmp_path):
    with pytest.raises(TypeError):
        Election(ELECTION_ID, GROUP, CANDIDATES, mod_exp=MOD_EXP,
                 ballots_path=tmp_path / "b.json")


def test_require_proof_without_verifier_is_configuration_error(tmp_path):
    with pytest.raises(ValueError):
        Election(ELECTION_ID, GROUP, CANDIDATES,
                 signature_verifier=verify_signature_stub, require_proof=True,
                 mod_exp=MOD_EXP, ballots_path=tmp_path / "b.json")


def test_state_names_and_errors_are_shared_across_modules():
    # Os nomes movidos para states.py continuam importáveis dos lugares antigos.
    for name in ("ElectionError", "ElectionStateError", "InvalidStateTransitionError",
                 "VotingPreconditionError", "ElectionState", "NEXT_STATE"):
        assert getattr(election_mod, name) is getattr(states_mod, name)
        assert getattr(election_pkg, name) is getattr(states_mod, name)
    assert issubclass(VotingPreconditionError, InvalidStateTransitionError)
    assert issubclass(VotingClosedError, states_mod.ElectionStateError)
    assert issubclass(InvalidBallotError, states_mod.ElectionError)


# =============================================================================
# Fluxo ponta a ponta
# =============================================================================
def _oracle_tally(env) -> list:
    """Oráculo de teste (a apuração real será server/tally.py)."""
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
    assert data["schema_version"] == 1
    assert data["election_id"] == ELECTION_ID
    assert data["state"] == "ENCERRADA"
    assert data["candidates"] == CANDIDATES
    assert data["joint_public_key"] == str(env.election.joint_public_key)
    assert len(data["ballots"]) == 3
    for record, receipt in zip(data["ballots"], receipts):
        sent = submitted[record["voter_id"]]
        payload = ballot_signing_payload(ELECTION_ID, record["voter_id"], _pairs(sent))
        expected = hashlib.sha256(payload + b"\n" + sent["signature"].encode("ascii")).hexdigest()
        assert record == {
            "index": receipt.index,
            "voter_id": receipt.voter_id,
            "ciphertexts": [{"c1": str(a), "c2": str(b)} for a, b in _pairs(sent)],
            "proof": None,
            "signature": sent["signature"],
            "receipt": expected,
        }
        assert receipt.receipt == expected == compute_receipt(payload, sent["signature"])

    # As cifras guardadas continuam somando certo: 2 votos para Alice, 1 para Bob.
    assert _oracle_tally(env) == [2, 1]


# =============================================================================
# Máquina de estados e state_provider
# =============================================================================
def test_next_state_is_the_official_linear_chain():
    states = list(ElectionState)
    assert [s.value for s in states] == OFFICIAL_STATES
    assert dict(NEXT_STATE) == {a: b for a, b in zip(states, states[1:])}
    assert ElectionState.AUDITADA not in NEXT_STATE          # terminal
    assert ElectionState.CONFIGURACAO not in NEXT_STATE.values()  # ninguém volta ao início
    with pytest.raises(TypeError):
        NEXT_STATE[ElectionState.AUDITADA] = ElectionState.CADASTRO  # somente leitura


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


def test_cadastro_to_encerrada_is_rejected(tmp_path, key_pool):
    env = _build(tmp_path, key_pool, open_voting=False)
    with pytest.raises(InvalidStateTransitionError):
        env.election.close_voting()
    assert env.election.current_state() == "CADASTRO"
    assert not env.ballots_path.exists()


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
    ballot = {
        "election_id": ELECTION_ID,
        "voter_id": "eleitor-1",
        "ciphertexts": [{"c1": 4, "c2": 4}, {"c1": 16, "c2": 16}],
        "signature": "AAAA",
    }
    with pytest.raises(VotingClosedError):
        env.election.submit_ballot(ballot)
    assert env.election.accepted_ballots == ()


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
def test_ineligible_voter_rejected(env, key_pool):
    calls_before = env.signature_verifier.call_count
    ballot = env.ballot("intruso", key=key_pool[3])
    with pytest.raises(IneligibleVoterError):
        env.election.submit_ballot(ballot)
    # A elegibilidade vem antes da assinatura: nem chegou a verificar.
    assert env.signature_verifier.call_count == calls_before
    assert env.election.accepted_ballots == ()


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
    ballot["voter_id"] = voter_id
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
# Validação estrutural da cédula
# =============================================================================
@pytest.mark.parametrize("field", ["election_id", "voter_id", "ciphertexts", "signature"])
def test_missing_field_rejected(env, field):
    ballot = env.ballot("eleitor-1")
    del ballot[field]
    with pytest.raises(InvalidBallotError, match="ausentes"):
        env.election.submit_ballot(ballot)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: "não é dict",
        lambda b: [b],
        lambda b: {**b, "extra": "contrabando"},
        lambda b: {**b, "election_id": "outra-eleicao"},
        lambda b: {**b, "ciphertexts": b["ciphertexts"][:1]},
        lambda b: {**b, "ciphertexts": b["ciphertexts"] * 2},
        lambda b: {**b, "ciphertexts": "lista"},
        lambda b: {**b, "ciphertexts": [[4, 4], [16, 16]]},
        lambda b: {**b, "ciphertexts": [{"c1": 4}, b["ciphertexts"][1]]},
    ],
    ids=["nao-dict", "lista", "campo-extra", "outra-eleicao", "cifras-a-menos",
         "cifras-a-mais", "cifras-str", "cifras-lista", "sem-c2"],
)
def test_malformed_ballot_rejected(env, mutate):
    with pytest.raises(InvalidBallotError):
        env.election.submit_ballot(mutate(env.ballot("eleitor-1")))
    assert env.election.accepted_ballots == ()


@pytest.mark.parametrize("bad", [True, False], ids=["True", "False"])
@pytest.mark.parametrize("field", ["c1", "c2"])
def test_bool_disguised_as_int_rejected(env, field, bad):
    ballot = env.ballot("eleitor-1")
    ballot["ciphertexts"][0][field] = bad
    calls_before = env.signature_verifier.call_count
    with pytest.raises(InvalidBallotError, match="deve ser int"):
        env.election.submit_ballot(ballot)
    assert env.signature_verifier.call_count == calls_before


@pytest.mark.parametrize("bad", ["4", 4.0, None, [4]], ids=["str", "float", "None", "lista"])
def test_non_int_component_rejected(env, bad):
    ballot = env.ballot("eleitor-1")
    ballot["ciphertexts"][1]["c2"] = bad
    with pytest.raises(InvalidBallotError, match="deve ser int"):
        env.election.submit_ballot(ballot)


@pytest.mark.parametrize("bad", [-5, 0, 1, P, P + 1])
@pytest.mark.parametrize("field", ["c1", "c2"])
def test_component_outside_range_rejected(env, field, bad):
    ballot = env.ballot("eleitor-1")
    ballot["ciphertexts"][1][field] = bad
    with pytest.raises(InvalidBallotError, match=r"\[2, p-1\]"):
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
# Assinatura digital
# =============================================================================
def test_tampered_ciphertext_after_signing_rejected(env):
    ballot = env.ballot("eleitor-1", (1, 0))
    ballot["ciphertexts"].reverse()  # troca o voto de candidato
    with pytest.raises(InvalidSignatureError):
        env.election.submit_ballot(ballot)
    assert issubclass(InvalidSignatureError, InvalidBallotError)


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
    voter_key, message, signature = env.signature_verifier.call_args.args
    assert voter_key == registered["eleitor-2"]
    assert type(message) is bytes and type(signature) is bytes


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


@pytest.mark.parametrize("result", [False, 1, "True", None, mock.sentinel.ok])
def test_signature_verifier_must_return_exactly_true(tmp_path, key_pool, result):
    env = _build(tmp_path, key_pool, signature_verifier=mock.Mock(return_value=result))
    with pytest.raises(InvalidSignatureError):
        env.election.submit_ballot(env.ballot("eleitor-1"))


def test_signature_verifier_exception_is_invalid_signature(tmp_path, key_pool):
    verifier = mock.Mock(side_effect=RuntimeError("falha interna"))
    env = _build(tmp_path, key_pool, signature_verifier=verifier)
    with pytest.raises(InvalidSignatureError):
        env.election.submit_ballot(env.ballot("eleitor-1"))


# =============================================================================
# Prova ZKP
# =============================================================================
def test_valid_proof_accepted_with_expected_arguments(tmp_path, key_pool):
    verifier = mock.Mock(side_effect=zkp_verifier_stub)
    env = _build(tmp_path, key_pool, proof_verifier=verifier)
    ballot = env.ballot("eleitor-1", with_proof=True)
    env.election.submit_ballot(ballot)

    proof_arg, cts_arg, group_arg, h_arg = verifier.call_args.args
    assert proof_arg == ballot["proof"] and proof_arg is not ballot["proof"]
    assert cts_arg == tuple(_pairs(ballot))
    assert group_arg is GROUP
    assert h_arg == env.election.joint_public_key
    assert _ballots_file(env)["ballots"][0]["proof"] == ballot["proof"]


def test_invalid_proof_rejected(tmp_path, key_pool):
    env = _build(tmp_path, key_pool, proof_verifier=mock.Mock(side_effect=zkp_verifier_stub))
    cts = [env.encrypt(1), env.encrypt(0)]
    wrong = {"scheme": "stub-zkp", "digest": "0" * 64}
    with pytest.raises(InvalidProofError):
        env.election.submit_ballot(env.signed("eleitor-1", cts, proof=wrong))
    assert issubclass(InvalidProofError, InvalidBallotError)
    assert not env.election.has_voted("eleitor-1")


@pytest.mark.parametrize("behavior", [1, "True", RuntimeError("x")], ids=["1", "str", "excecao"])
def test_proof_verifier_must_return_exactly_true(tmp_path, key_pool, behavior):
    verifier = (mock.Mock(side_effect=behavior) if isinstance(behavior, Exception)
                else mock.Mock(return_value=behavior))
    env = _build(tmp_path, key_pool, proof_verifier=verifier)
    with pytest.raises(InvalidProofError):
        env.election.submit_ballot(env.ballot("eleitor-1", with_proof=True))


def test_proof_without_verifier_rejected(env):
    with pytest.raises(InvalidProofError, match="verificador"):
        env.election.submit_ballot(env.ballot("eleitor-1", with_proof=True))


def test_required_proof_missing_rejected(tmp_path, key_pool):
    env = _build(tmp_path, key_pool, proof_verifier=mock.Mock(side_effect=zkp_verifier_stub),
                 require_proof=True)
    with pytest.raises(InvalidProofError, match="exige"):
        env.election.submit_ballot(env.ballot("eleitor-1"))


@pytest.mark.parametrize("mutate", [
    lambda b: b.pop("proof"),
    lambda b: b.__setitem__("proof", {"scheme": "stub-zkp", "digest": "f" * 64}),
], ids=["removida", "trocada"])
def test_proof_changed_after_signing_rejected(tmp_path, key_pool, mutate):
    env = _build(tmp_path, key_pool, proof_verifier=mock.Mock(side_effect=zkp_verifier_stub))
    ballot = env.ballot("eleitor-1", with_proof=True)
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


def test_accepted_ballots_are_immutable(tmp_path, key_pool):
    env = _build(tmp_path, key_pool, proof_verifier=mock.Mock(side_effect=zkp_verifier_stub))
    ballot = env.ballot("eleitor-1", with_proof=True)
    env.election.submit_ballot(ballot)

    record = env.election.accepted_ballots[0]
    assert isinstance(env.election.accepted_ballots, tuple)
    assert isinstance(record, AcceptedBallot)
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.voter_id = "outro"

    original_proof = copy.deepcopy(ballot["proof"])
    ballot["proof"]["digest"] = "adulterado"
    ballot["ciphertexts"][0]["c1"] = 4
    exported = record.to_dict()
    exported["proof"]["digest"] = "adulterado"
    assert record.to_dict()["proof"] == original_proof
    assert record.ciphertexts[0][0] != 4


@pytest.mark.skipif(not CRYPTO_GROUP_STUBBED, reason="só quando src.crypto.group é simulado")
def test_subgroup_checks_use_injected_mod_exp(env):
    MOD_EXP.reset_mock()
    ballot = env.ballot("eleitor-1")
    env.election.submit_ballot(ballot)
    called = {c.args for c in MOD_EXP.call_args_list}
    for c1, c2 in _pairs(ballot):
        assert (c1, Q, P) in called and (c2, Q, P) in called


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
    if HAVE_CRYPTOGRAPHY:
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