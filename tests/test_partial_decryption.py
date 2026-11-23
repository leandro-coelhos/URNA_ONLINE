"""Testes da decifração conjunta do resultado (Issue #11).

Cobre ``src/authorities/partial_decryption.py``:
- ponta a ponta com 3 e 4 autoridades e 2 candidatos (inclusive total 0);
- falha da apuração quando falta qualquer autoridade;
- rejeição de parcelas inválidas, não cadastradas, duplicadas, incompletas
  ou fora de ``APURACAO``/sem congelamento;
- ausência de ``x_i``, ``Σ x_i`` e ``w`` em estruturas, arquivos públicos e
  exceções.

Independência de branch
-----------------------
- ``src.crypto.group.mod_exp``: simulado com ``unittest.mock`` só se não
  existir; em qualquer caso, injetado como ``mod_exp=MOD_EXP``.
- ``mod_inv`` e ``discrete_log``: sempre injetados com oráculos de teste
  (``oracle_mod_inv`` e ``oracle_discrete_log``), pois a interface real do
  módulo de crypto ainda não está fixada.

O teste faz o papel do cliente do eleitor (cifra com ``pow``), do agregador
(produto das cifras) e de cada autoridade (objetos ``Authority`` locais).
Nada disso existe em ``src/``.
"""

import dataclasses
import importlib
import json
import secrets
import sys
import traceback
import types
from pathlib import Path
from types import SimpleNamespace
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

from src.authorities.authority import (  # noqa: E402
    Authority,
    key_path,
    publish_joint_public_key,
)
from src.authorities.partial_decryption import (  # noqa: E402
    AuthorityPartialSubmission,
    CandidatePartialShare,
    DecryptionError,
    DuplicateShareError,
    InvalidShareError,
    MissingAuthorityShareError,
    PartialDecryptionCollector,
    PartialDecryptionError,
    TallyStateError,
    UnregisteredAuthorityError,
    combine_and_decrypt_result,
    compute_authority_partials,
    load_public_json,
    verify_authority_partials,
)
from src.election.states import ElectionState  # noqa: E402

pd_mod = sys.modules["src.authorities.partial_decryption"]
REAL_RANDBELOW = secrets.randbelow


# =============================================================================
# Grupo, oráculos e constantes
# =============================================================================
# RFC 3526, grupo 14 (MODP 2048 bits): p primo seguro, q = (p-1)/2 primo e
# g = 2 gera o subgrupo de ordem q (p ≡ 7 mod 8).
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
NON_RESIDUE = next(a for a in range(3, 1000) if pow(a, Q, P) == P - 1)

ELECTION_ID = "eleicao-2026"
CANDIDATES = ["Alice", "Bob"]
APURACAO = ElectionState.APURACAO


def oracle_mod_inv(value: int, modulus: int) -> int:
    """Oráculo de teste (o real virá de src.crypto)."""
    return pow(value, -1, modulus)


def oracle_discrete_log(target: int, base: int, modulus: int, max_exp: int):
    """Oráculo de teste: menor t em [0, max_exp] com base^t ≡ target."""
    acc = 1
    for t in range(max_exp + 1):
        if acc == target:
            return t
        acc = acc * base % modulus
    return None


# =============================================================================
# Ambiente
# =============================================================================
@dataclasses.dataclass
class Env:
    authorities: list
    election_data: dict
    aggregate_data: dict
    expected: dict
    randomness: list
    private_dir: Path
    public_dir: Path

    @property
    def election_path(self) -> Path:
        return self.public_dir / "election.json"

    @property
    def aggregate_path(self) -> Path:
        return self.public_dir / "aggregate_ciphertexts.json"

    @property
    def partials_path(self) -> Path:
        return self.public_dir / "authority_partials.json"

    @property
    def result_path(self) -> Path:
        return self.public_dir / "result.json"

    @property
    def ids(self) -> list:
        return [a.authority_id for a in self.authorities]

    def private_xs(self) -> list:
        # O teste lê os arquivos privados como oráculo; o código testado nunca.
        return [json.loads(key_path(i, self.private_dir).read_text())["x"] for i in self.ids]

    def partial(self, authority, **kwargs) -> AuthorityPartialSubmission:
        kwargs.setdefault("election_state", APURACAO)
        return compute_authority_partials(
            authority, self.election_data, self.aggregate_data, mod_exp=MOD_EXP, **kwargs
        )

    def all_partials(self) -> list:
        return [self.partial(a) for a in self.authorities]

    def collector(self, **kwargs) -> PartialDecryptionCollector:
        kwargs.setdefault("election_state", APURACAO)
        election_data = kwargs.pop("election_data", self.election_data)
        return PartialDecryptionCollector(
            election_data, self.aggregate_data, mod_exp=MOD_EXP, **kwargs
        )

    def combine(self, submissions, **kwargs) -> dict:
        kwargs.setdefault("election_state", APURACAO)
        election_data = kwargs.pop("election_data", self.election_data)
        return combine_and_decrypt_result(
            election_data,
            self.aggregate_data,
            submissions,
            result_path=self.result_path,
            mod_exp=MOD_EXP,
            mod_inv=kwargs.pop("mod_inv", oracle_mod_inv),
            discrete_log=kwargs.pop("discrete_log", oracle_discrete_log),
            **kwargs,
        )


DEFAULT_CHOICES = ("Alice", "Bob", "Alice", "Bob", "Alice")


def _build(tmp_path, *, n_authorities=3, choices=DEFAULT_CHOICES) -> Env:
    private_dir = tmp_path / "data" / "private"
    public_dir = tmp_path / "data" / "public"

    # Cada autoridade gera a própria chave; o arquivo fica em data/private/.
    authorities = [
        Authority.generate(str(i), GROUP, private_dir) for i in range(1, n_authorities + 1)
    ]

    # Um eleitor a mais que as cédulas: max_votes inferido = len(voters).
    n_voters = len(choices) + 1
    public_data = {
        "schema_version": 1,
        "election_id": ELECTION_ID,
        "frozen": True,
        "voters": [
            {"voter_id": f"eleitor-{i}", "public_key": f"PK-{i}"} for i in range(1, n_voters + 1)
        ],
        "authorities": [
            {"authority_id": a.authority_id, "public_key": str(a.public_key().h)}
            for a in authorities
        ],
    }
    publish_joint_public_key(public_data, GROUP, public_dir / "election.json")
    election_data = load_public_json(public_dir / "election.json")
    h = int(election_data["joint_public_key"])

    # Cliente do eleitor + agregação homomórfica (produto das cifras).
    randomness = []
    aggregate = {cid: [1, 1] for cid in CANDIDATES}
    for choice in choices:
        for cid in CANDIDATES:
            m = 1 if choice == cid else 0
            r = 2 + secrets.randbelow(Q - 2)
            randomness.append(r)
            aggregate[cid][0] = aggregate[cid][0] * pow(G, r, P) % P
            aggregate[cid][1] = aggregate[cid][1] * (pow(G, m, P) * pow(h, r, P) % P) % P
    aggregate_data = {
        "election_id": ELECTION_ID,
        "ciphertexts": {cid: {"c1": str(c1), "c2": str(c2)} for cid, (c1, c2) in aggregate.items()},
    }
    (public_dir / "aggregate_ciphertexts.json").write_text(json.dumps(aggregate_data, indent=2))
    aggregate_data = load_public_json(public_dir / "aggregate_ciphertexts.json")

    expected = {cid: choices.count(cid) for cid in CANDIDATES}
    return Env(authorities, election_data, aggregate_data, expected, randomness,
               private_dir, public_dir)


@pytest.fixture
def env(tmp_path):
    return _build(tmp_path)


def _tamper(submission, candidate_id, **changes) -> AuthorityPartialSubmission:
    """Copia a submissão alterando campos de uma parcela (sem refazer a prova)."""
    shares = tuple(
        dataclasses.replace(share, **changes) if share.candidate_id == candidate_id else share
        for share in submission.shares
    )
    return AuthorityPartialSubmission(submission.authority_id, shares)


# =============================================================================
# Configuração
# =============================================================================
def test_group_parameters_are_rfc3526_2048():
    assert P.bit_length() == 2048 and Q.bit_length() >= 224
    assert P == 2 * Q + 1
    assert pow(G, Q, P) == 1
    assert pow(NON_RESIDUE, Q, P) == P - 1


def test_oracles_are_consistent():
    assert oracle_mod_inv(16, P) * 16 % P == 1
    assert oracle_discrete_log(pow(G, 7, P), G, P, 10) == 7
    assert oracle_discrete_log(1, G, P, 10) == 0
    assert oracle_discrete_log(pow(G, 11, P), G, P, 10) is None


# =============================================================================
# 1. Fluxo ponta a ponta
# =============================================================================
@pytest.mark.parametrize("n_authorities", [3, 4])
@pytest.mark.parametrize(
    "choices",
    [DEFAULT_CHOICES, ("Alice", "Alice", "Alice")],
    ids=["3x2", "bob-zero"],
)
def test_end_to_end(tmp_path, n_authorities, choices):
    env = _build(tmp_path, n_authorities=n_authorities, choices=choices)

    # Chaves privadas: um arquivo por autoridade, só em data/private/.
    assert sorted(p.name for p in env.private_dir.iterdir()) == sorted(
        f"authority_{i}.key" for i in env.ids
    )
    assert not list(env.public_dir.glob("*.key"))

    # Cada autoridade calcula localmente; o servidor valida todas.
    collector = env.collector()
    for authority in env.authorities:
        submission = env.partial(authority)
        assert isinstance(submission, AuthorityPartialSubmission)
        assert submission.candidate_ids == frozenset(CANDIDATES)
        collector.submit(submission)
    assert collector.is_complete
    assert collector.missing_authorities == ()

    # authority_partials.json: gravado e recarregado com reverificação.
    saved = collector.save(env.partials_path)
    on_disk = json.loads(env.partials_path.read_text())
    assert on_disk == saved
    assert on_disk["election_id"] == ELECTION_ID
    assert [p["authority_id"] for p in on_disk["partials"]] == env.ids
    reloaded = PartialDecryptionCollector.load(
        env.election_data, env.aggregate_data, env.partials_path,
        election_state=APURACAO, mod_exp=MOD_EXP,
    )
    assert reloaded.submissions == collector.submissions

    # Combinação de todas as parcelas e result.json.
    result = env.combine(reloaded)
    assert result["totals"] == env.expected
    assert result["election_id"] == ELECTION_ID
    assert result["authorities"] == env.ids
    assert result["max_votes"] == len(choices) + 1
    assert json.loads(env.result_path.read_text()) == result
    if choices == ("Alice", "Alice", "Alice"):
        assert result["totals"]["Bob"] == 0


def test_combine_accepts_plain_list_of_submissions(env):
    result = env.combine(env.all_partials())
    assert result["totals"] == env.expected


def test_combine_with_explicit_max_votes(env):
    assert env.combine(env.all_partials(), max_votes=3)["totals"] == env.expected


def test_verify_authority_partials_function(env):
    submission = env.partial(env.authorities[0])
    verify_authority_partials(submission, env.election_data, env.aggregate_data,
                              election_state=APURACAO, mod_exp=MOD_EXP)
    with pytest.raises(InvalidShareError):
        verify_authority_partials(
            _tamper(submission, "Alice", s=(submission.share_for("Alice").s + 1) % Q),
            env.election_data, env.aggregate_data, mod_exp=MOD_EXP,
        )


def test_submission_roundtrip_through_dict(env):
    submission = env.partial(env.authorities[0])
    assert AuthorityPartialSubmission.from_dict(submission.to_dict()) == submission


# =============================================================================
# 2. Apuração sem uma autoridade falha
# =============================================================================
@pytest.mark.parametrize("n_authorities", [3, 4])
def test_missing_one_authority_fails(tmp_path, n_authorities):
    env = _build(tmp_path, n_authorities=n_authorities)
    partials = env.all_partials()[:-1]  # falta a última autoridade

    collector = env.collector()
    for submission in partials:
        collector.submit(submission)
    assert not collector.is_complete
    assert collector.missing_authorities == (env.ids[-1],)

    for source in (collector, partials):
        with pytest.raises(MissingAuthorityShareError):
            env.combine(source)
    assert not env.result_path.exists()


def test_missing_authority_even_with_three_or_more_present(tmp_path):
    # 4 cadastradas, 3 enviadas: o mínimo (3) não basta, é preciso TODAS.
    env = _build(tmp_path, n_authorities=4)
    with pytest.raises(MissingAuthorityShareError):
        env.combine(env.all_partials()[1:])
    assert not env.result_path.exists()


def test_combine_without_any_partial_fails(env):
    with pytest.raises(MissingAuthorityShareError):
        env.combine([])
    assert not env.result_path.exists()


# =============================================================================
# 3. Participações inválidas
# =============================================================================
def test_tampered_d_after_proof_rejected(env):
    submission = env.partial(env.authorities[0])
    d = submission.share_for("Alice").d
    tampered = _tamper(submission, "Alice", d=d * G % P)  # ainda no subgrupo
    collector = env.collector()
    with pytest.raises(InvalidShareError, match="prova"):
        collector.submit(tampered)
    assert collector.submissions == ()


@pytest.mark.parametrize("field", ["a1", "a2", "s"])
def test_tampered_proof_rejected(env, field):
    submission = env.partial(env.authorities[0])
    share = submission.share_for("Bob")
    if field == "s":
        new_value = (share.s + 1) % Q
    else:
        new_value = getattr(share, field) * G % P  # ainda no subgrupo
    with pytest.raises(InvalidShareError, match="prova"):
        env.collector().submit(_tamper(submission, "Bob", **{field: new_value}))


def test_proof_with_other_authority_key_rejected(env):
    # Autoridade 2 tenta se passar pela 1 reaproveitando as próprias parcelas.
    submission_2 = env.partial(env.authorities[1])
    impostor = AuthorityPartialSubmission(env.ids[0], submission_2.shares)
    with pytest.raises(InvalidShareError):
        env.collector().submit(impostor)


def test_valid_proof_for_unregistered_key_rejected(env):
    # Prova internamente coerente, mas feita com outra chave privada: o
    # servidor verifica contra o h_1 de election.json e recusa.
    ctx = pd_mod._parse_election(env.election_data, MOD_EXP)
    aggregate = pd_mod._parse_aggregate(env.aggregate_data, ctx, MOD_EXP)
    impostor = Authority(env.ids[0], GROUP, 2 + secrets.randbelow(Q - 2))
    shares = tuple(
        pd_mod._prove_share(impostor, ctx, cid, aggregate[cid][0], impostor.public_key().h, MOD_EXP)
        for cid in sorted(aggregate)
    )
    with pytest.raises(InvalidShareError, match="prova"):
        env.collector().submit(AuthorityPartialSubmission(env.ids[0], shares))


def test_local_key_mismatch_refused_before_computing(env):
    impostor = Authority(env.ids[0], GROUP, 2 + secrets.randbelow(Q - 2))
    with pytest.raises(PartialDecryptionError, match="não corresponde"):
        env.partial(impostor)


@pytest.mark.parametrize("bad", [1, P - 1, NON_RESIDUE, 0, P], ids=["um", "p-1", "nao-residuo", "zero", "p"])
@pytest.mark.parametrize("field", ["d", "a1", "a2"])
def test_component_outside_subgroup_rejected(env, field, bad):
    submission = env.partial(env.authorities[0])
    with pytest.raises(InvalidShareError):
        env.collector().submit(_tamper(submission, "Alice", **{field: bad}))


@pytest.mark.parametrize("bad", [Q, Q + 1, -1])
def test_s_outside_range_rejected(env, bad):
    submission = env.partial(env.authorities[0])
    with pytest.raises(InvalidShareError, match=r"\[0, q\)"):
        env.collector().submit(_tamper(submission, "Alice", s=bad))


@pytest.mark.parametrize("bad", [True, False], ids=["True", "False"])
@pytest.mark.parametrize("field", ["d", "a1", "a2", "s"])
def test_bool_disguised_as_int_rejected(env, field, bad):
    submission = env.partial(env.authorities[0])
    # Já na construção da estrutura pública…
    with pytest.raises(InvalidShareError):
        _tamper(submission, "Alice", **{field: bad})
    # …e também ao ler do JSON.
    raw = submission.to_dict()
    raw["shares"]["Alice"][field] = bad
    with pytest.raises(InvalidShareError):
        AuthorityPartialSubmission.from_dict(raw)


@pytest.mark.parametrize("bad", ["-5", "0012", " 5", "5.0", "abc", None, 5.0])
def test_malformed_numbers_in_json_rejected(env, bad):
    raw = env.partial(env.authorities[0]).to_dict()
    raw["shares"]["Bob"]["d"] = bad
    with pytest.raises(InvalidShareError):
        AuthorityPartialSubmission.from_dict(raw)


def test_unregistered_authority_rejected(env, tmp_path):
    outsider = Authority.generate("99", GROUP, tmp_path / "outra" / "private")
    with pytest.raises(UnregisteredAuthorityError):
        env.partial(outsider)

    borrowed = env.partial(env.authorities[0])
    collector = env.collector()
    with pytest.raises(UnregisteredAuthorityError):
        collector.submit(AuthorityPartialSubmission("99", borrowed.shares))
    assert collector.submissions == ()


@pytest.mark.parametrize("bad_id", ["../evil", "a/b", ""])
def test_malformed_authority_id_rejected(env, bad_id):
    shares = env.partial(env.authorities[0]).shares
    with pytest.raises(InvalidShareError):
        AuthorityPartialSubmission(bad_id, shares)


def test_duplicate_submission_rejected_and_first_preserved(env):
    collector = env.collector()
    first = env.partial(env.authorities[0])
    collector.submit(first)
    for again in (first, env.partial(env.authorities[0])):  # reenvio e recálculo
        with pytest.raises(DuplicateShareError):
            collector.submit(again)
    assert collector.submissions == (first,)


def test_missing_candidate_rejected(env):
    submission = env.partial(env.authorities[0])
    incomplete = AuthorityPartialSubmission(submission.authority_id,
                                            (submission.share_for("Alice"),))
    with pytest.raises(InvalidShareError, match="faltando"):
        env.collector().submit(incomplete)


def test_extra_candidate_rejected(env):
    submission = env.partial(env.authorities[0])
    extra = dataclasses.replace(submission.share_for("Alice"), candidate_id="Carol")
    with pytest.raises(InvalidShareError, match="sobrando"):
        env.collector().submit(
            AuthorityPartialSubmission(submission.authority_id, submission.shares + (extra,))
        )


def test_duplicate_candidate_inside_submission_rejected(env):
    share = env.partial(env.authorities[0]).share_for("Alice")
    with pytest.raises(InvalidShareError, match="repetido"):
        AuthorityPartialSubmission(env.ids[0], (share, share))


# --- estado da eleição e congelamento ----------------------------------------
@pytest.mark.parametrize("state", [
    ElectionState.CADASTRO, ElectionState.VOTACAO_ABERTA, ElectionState.ENCERRADA,
    ElectionState.AUDITADA, "ENCERRADA", "ESTADO_INEXISTENTE",
])
def test_outside_apuracao_rejected(env, state):
    authority = env.authorities[0]
    with pytest.raises(TallyStateError):
        env.partial(authority, election_state=state)
    with pytest.raises(TallyStateError):
        env.collector(election_state=state)
    partials = [env.partial(a) for a in env.authorities]
    with pytest.raises(TallyStateError):
        env.combine(partials, election_state=state)
    assert not env.result_path.exists()


def test_state_is_rechecked_on_every_submission(env):
    current = {"state": "APURACAO"}
    collector = env.collector(election_state=lambda: current["state"])
    partials = env.all_partials()
    collector.submit(partials[0])
    current["state"] = "AUDITADA"
    with pytest.raises(TallyStateError):
        collector.submit(partials[1])
    assert len(collector.submissions) == 1


def test_apuracao_accepted_as_string_or_provider(env):
    env.collector(election_state="APURACAO")
    env.collector(election_state=lambda: "APURACAO")
    env.collector(election_state=None)  # etapa não informada: só o congelamento é exigido


def test_unfrozen_registration_rejected(env):
    unfrozen = dict(env.election_data, frozen=False)
    with pytest.raises(TallyStateError, match="congelado"):
        compute_authority_partials(env.authorities[0], unfrozen, env.aggregate_data,
                                   election_state=APURACAO, mod_exp=MOD_EXP)
    with pytest.raises(TallyStateError):
        env.collector(election_data=unfrozen)
    with pytest.raises(TallyStateError):
        env.combine(env.all_partials(), election_data=unfrozen)
    assert not env.result_path.exists()


def test_tally_state_error_is_partial_decryption_error():
    for exc in (TallyStateError, UnregisteredAuthorityError, DuplicateShareError,
                InvalidShareError, MissingAuthorityShareError, DecryptionError):
        assert issubclass(exc, PartialDecryptionError)


# --- dados públicos de entrada --------------------------------------------------
@pytest.mark.parametrize("bad", [True, 1, "1", P - 1, NON_RESIDUE, "abc", "0012"],
                         ids=["bool", "um-int", "um-str", "p-1", "nao-residuo", "texto", "zeros"])
def test_malformed_aggregate_c1_rejected(env, bad):
    aggregate = json.loads(json.dumps(env.aggregate_data))
    aggregate["ciphertexts"]["Alice"]["c1"] = bad
    with pytest.raises(PartialDecryptionError):
        compute_authority_partials(env.authorities[0], env.election_data, aggregate,
                                   election_state=APURACAO, mod_exp=MOD_EXP)
    with pytest.raises(PartialDecryptionError):
        PartialDecryptionCollector(env.election_data, aggregate, mod_exp=MOD_EXP)


@pytest.mark.parametrize("bad", [True, P - 1, NON_RESIDUE])
def test_malformed_aggregate_c2_rejected_before_combining(env, bad):
    partials = env.all_partials()
    aggregate = json.loads(json.dumps(env.aggregate_data))
    aggregate["ciphertexts"]["Bob"]["c2"] = bad
    with pytest.raises(PartialDecryptionError):
        combine_and_decrypt_result(env.election_data, aggregate, partials,
                                   result_path=env.result_path, mod_exp=MOD_EXP,
                                   mod_inv=oracle_mod_inv, discrete_log=oracle_discrete_log)
    assert not env.result_path.exists()


def test_aggregate_from_other_election_rejected(env):
    aggregate = dict(env.aggregate_data, election_id="outra-eleicao")
    with pytest.raises(PartialDecryptionError, match="outra eleição"):
        compute_authority_partials(env.authorities[0], env.election_data, aggregate,
                                   mod_exp=MOD_EXP)


def test_tampered_joint_public_key_rejected(env):
    election = dict(env.election_data, joint_public_key=str(pow(G, 12345, P)))
    with pytest.raises(PartialDecryptionError, match="joint_public_key"):
        env.collector(election_data=election)


def test_tampered_partials_file_rejected_on_load(env):
    collector = env.collector()
    for submission in env.all_partials():
        collector.submit(submission)
    collector.save(env.partials_path)

    data = json.loads(env.partials_path.read_text())
    share = data["partials"][1]["shares"]["Alice"]
    share["d"] = str(int(share["d"]) * G % P)
    env.partials_path.write_text(json.dumps(data))
    with pytest.raises(InvalidShareError):
        PartialDecryptionCollector.load(env.election_data, env.aggregate_data,
                                        env.partials_path, mod_exp=MOD_EXP)


# --- falhas na recuperação do total ---------------------------------------------
def test_total_above_max_votes_fails(env):
    # Alice tem 3 votos; com max_votes=2 nenhum t em [0, 2] corresponde.
    with pytest.raises(DecryptionError, match="Alice"):
        env.combine(env.all_partials(), max_votes=2)
    assert not env.result_path.exists()


@pytest.mark.parametrize("liar", [
    lambda target, base, mod, max_exp: 0,         # valor errado
    lambda target, base, mod, max_exp: True,      # bool disfarçado
    lambda target, base, mod, max_exp: -1,        # fora do intervalo
    lambda target, base, mod, max_exp: None,      # sem solução
], ids=["errado", "bool", "negativo", "none"])
def test_wrong_discrete_log_result_is_detected(env, liar):
    with pytest.raises(DecryptionError):
        env.combine(env.all_partials(), discrete_log=liar)
    assert not env.result_path.exists()


def test_wrong_modular_inverse_is_detected(env):
    with pytest.raises(DecryptionError, match="inverso"):
        env.combine(env.all_partials(), mod_inv=lambda value, modulus: 2)
    assert not env.result_path.exists()


# =============================================================================
# 4. Chaves privadas e efêmeros nunca saem da autoridade
# =============================================================================
def test_no_secrets_in_public_structures_or_files(env):
    ephemeral = []

    def recording_randbelow(n):
        value = REAL_RANDBELOW(n)
        ephemeral.append(value + 2)  # w = randbelow(q - 2) + 2
        return value

    with mock.patch.object(pd_mod.secrets, "randbelow", side_effect=recording_randbelow):
        partials = env.all_partials()
    assert len(ephemeral) == len(env.authorities) * len(CANDIDATES)

    collector = env.collector()
    for submission in partials:
        collector.submit(submission)
    collector.save(env.partials_path)
    env.combine(collector)

    xs = env.private_xs()
    secret_values = {str(x) for x in xs} | {str(sum(xs)), str(sum(xs) % Q)}
    secret_values |= {str(w) for w in ephemeral}

    # Estruturas públicas: só os campos previstos.
    for submission in partials:
        assert {f.name for f in dataclasses.fields(submission)} == {"authority_id", "shares"}
        for share in submission.shares:
            assert {f.name for f in dataclasses.fields(share)} == {"candidate_id", "d", "a1", "a2", "s"}
        public_texts = [repr(submission), json.dumps(submission.to_dict())]
        for text in public_texts:
            for secret in secret_values:
                assert secret not in text

    # Arquivos públicos: nenhum segredo, nenhuma chave privada.
    names = sorted(p.name for p in env.public_dir.iterdir())
    assert names == ["aggregate_ciphertexts.json", "authority_partials.json",
                     "election.json", "result.json"]
    for path in env.public_dir.iterdir():
        text = path.read_text(encoding="utf-8")
        assert '"x"' not in text
        for secret in secret_values:
            assert secret not in text, f"segredo vazou em {path.name}"

    # Memória do servidor (coletor) também só com dados públicos.
    collector_repr = repr(vars(collector)) + json.dumps(collector.to_dict())
    for secret in secret_values:
        assert secret not in collector_repr


def test_local_failure_does_not_leak_secret_in_exception(env):
    authority = env.authorities[0]
    x = env.private_xs()[0]

    def leaky_mod_exp(base, exponent, modulus):
        if exponent == x:
            raise RuntimeError(f"falha interna com expoente {exponent}")
        return MOD_EXP(base, exponent, modulus)

    with pytest.raises(PartialDecryptionError) as info:
        compute_authority_partials(authority, env.election_data, env.aggregate_data,
                                   election_state=APURACAO, mod_exp=leaky_mod_exp)
    exc = info.value
    # Lançada fora do except: sem exceção original encadeada.
    assert exc.__cause__ is None and exc.__context__ is None
    rendered = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    assert str(x) not in rendered
    assert str(x) not in str(exc)


def test_authority_does_not_expose_private_key(env):
    authority = env.authorities[0]
    x = env.private_xs()[0]
    assert not hasattr(authority, "x")
    assert str(x) not in repr(authority)
    assert str(x) not in repr(authority.public_key())