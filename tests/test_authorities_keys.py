"""Testes das chaves das autoridades e da integração com o cadastro oficial.

Módulos reais, sem stubs: nada é substituído em ``sys.modules``. A
exponenciação modular é o ``pow`` nativo, padrão do projeto.
"""

import dataclasses
import importlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


authority_mod = importlib.import_module("src.authorities.authority")
registration_mod = importlib.import_module("src.server.registration")

authority_mod = importlib.import_module("src.authorities.authority")

from src.authorities.authority import (  # noqa: E402
    Authority,
    AuthorityPublicKey,
    MIN_AUTHORITIES,
    JointKeyError,
    compute_joint_public_key,
    generate_authorities,
    key_path,
    publish_joint_public_key,
    validate_authority_id,
)

try:
    registration_mod = importlib.import_module("src.server.registration")
    from src.server.registration import Authority as RegisteredAuthority  # noqa: E402
    from src.server.registration import (  # noqa: E402
        DuplicateParticipantError,
        InvalidIdentifierError,
        InvalidPublicKeyError,
        Registration,
        RegistrationClosedError,
    )
    HAS_REGISTRATION = True
except ModuleNotFoundError:
    HAS_REGISTRATION = False

# RFC 3526, grupo 14 (MODP 2048 bits): p é primo seguro, q = (p-1)/2 é primo
# e, como p ≡ 7 (mod 8), g = 2 é resíduo quadrático e gera o subgrupo de ordem q.
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
# Menor não-resíduo quadrático (a^q ≡ -1 mod p): fora do subgrupo de ordem q.
NON_RESIDUE = next(a for a in range(3, 1000) if pow(a, GROUP.q, GROUP.p) == GROUP.p - 1)


@pytest.fixture
def dirs(tmp_path):
    return tmp_path / "data" / "private", tmp_path / "data" / "public" / "election.json"


@pytest.fixture
def registration():
    if not HAS_REGISTRATION:
        pytest.skip("src.server.registration ainda não está na main")
    return Registration("eleicao-2026", p=GROUP.p, q=GROUP.q, state_provider=lambda: "CADASTRO")


def _read_private_x(private_dir: Path, authority_id: str) -> int:
    # Leitura direta do arquivo: só o teste age como "oráculo" aqui.
    return json.loads(key_path(authority_id, private_dir).read_text())["x"]


def _register_all(registration, public_keys):
    return [registration.register_authority(pk.authority_id, pk.h) for pk in public_keys]


def test_group_parameters_meet_registration_requirements():
    assert GROUP.p.bit_length() >= 2048
    assert GROUP.q.bit_length() >= 224
    assert GROUP.p == 2 * GROUP.q + 1
    assert pow(GROUP.g, GROUP.q, GROUP.p) == 1 and GROUP.g != 1


# ----------------------------------------------------------------------------
# authority_id como str, com a mesma regra do cadastro
# ----------------------------------------------------------------------------
@pytest.mark.skipif(not HAS_REGISTRATION, reason="src.server.registration ainda não está na main")
@pytest.mark.parametrize(
    "candidate",
    ["1", "A", "aut-1", "aut_2", "x" * 64, "", "x" * 65, "-1", "_a", "a b", "a/b",
     "../1", "1.0", "ção", " 1", "1\n", 1, None, True],
)
def test_authority_id_rule_matches_registration(candidate):
    def accepted(validator, exc):
        try:
            validator(candidate)
            return True
        except exc:
            return False

    ours = accepted(validate_authority_id, ValueError)
    theirs = accepted(registration_mod._validate_identifier, InvalidIdentifierError)
    assert ours == theirs


@pytest.mark.parametrize("bad_id", ["../evil", "a/b", "", 1, "-x"])
def test_key_path_rejects_invalid_ids(bad_id, dirs):
    private_dir, _ = dirs
    with pytest.raises(ValueError):
        key_path(bad_id, private_dir)
    with pytest.raises(ValueError):
        Authority(bad_id, GROUP, 5)


def test_generate_authorities_uses_string_ids(dirs):
    private_dir, _ = dirs
    public_keys = generate_authorities(3, GROUP, private_dir)
    assert [pk.authority_id for pk in public_keys] == ["1", "2", "3"]
    for pk in public_keys:
        assert isinstance(pk, AuthorityPublicKey)
        assert {f.name for f in dataclasses.fields(pk)} == {"authority_id", "h"}


# ----------------------------------------------------------------------------
# Mínimo de três autoridades
# ----------------------------------------------------------------------------
def test_min_authorities_is_three():
    assert MIN_AUTHORITIES == 3


@pytest.mark.parametrize("n", [1, 2])
def test_generate_authorities_requires_at_least_three(dirs, n):
    private_dir, _ = dirs
    with pytest.raises(ValueError):
        generate_authorities(n, GROUP, private_dir)
    assert not private_dir.exists() or not any(private_dir.iterdir())


@pytest.mark.parametrize("n", [0, -1, "3", 3.0, True])
def test_generate_authorities_rejects_invalid_n(dirs, n):
    private_dir, _ = dirs
    with pytest.raises(ValueError):
        generate_authorities(n, GROUP, private_dir)


def _export_with_n_registered(registration, private_dir, n):
    # generate_authorities exige >= 3; registramos só as n primeiras.
    public_keys = generate_authorities(3, GROUP, private_dir)
    _register_all(registration, public_keys[:n])
    return registration.export_public_data()


@pytest.mark.parametrize("n", [1, 2])
def test_compute_joint_key_requires_at_least_three(dirs, registration, n):
    private_dir, _ = dirs
    public_data = _export_with_n_registered(registration, private_dir, n)
    assert len(public_data["authorities"]) == n
    with pytest.raises(JointKeyError):
        compute_joint_public_key(public_data, GROUP)


@pytest.mark.parametrize("n", [1, 2])
def test_publish_joint_key_requires_at_least_three(dirs, registration, n):
    private_dir, election_path = dirs
    public_data = _export_with_n_registered(registration, private_dir, n)
    with pytest.raises(JointKeyError):
        publish_joint_public_key(public_data, GROUP, election_path)
    assert not election_path.exists(), "nada deve ser publicado sem 3 autoridades"


def test_publish_failure_keeps_existing_election_json(dirs, registration):
    private_dir, election_path = dirs
    election_path.parent.mkdir(parents=True)
    election_path.write_text('{"name": "Eleição teste"}')
    public_data = _export_with_n_registered(registration, private_dir, 2)
    with pytest.raises(JointKeyError):
        publish_joint_public_key(public_data, GROUP, election_path)
    assert election_path.read_text() == '{"name": "Eleição teste"}'


def test_min_authorities_is_forwarded_by_publish(dirs, registration):
    private_dir, election_path = dirs
    public_data = _export_with_n_registered(registration, private_dir, 3)
    with pytest.raises(JointKeyError):
        publish_joint_public_key(public_data, GROUP, election_path, min_authorities=4)
    assert not election_path.exists()
    publish_joint_public_key(public_data, GROUP, election_path, min_authorities=3)
    assert election_path.exists()


@pytest.mark.parametrize("bad_min", [0, -1, "3", True])
def test_min_authorities_parameter_is_validated(bad_min):
    data = {"authorities": [{"authority_id": str(i), "public_key": "4"} for i in range(3)]}
    with pytest.raises(ValueError):
        compute_joint_public_key(data, GROUP, min_authorities=bad_min)


# ----------------------------------------------------------------------------
# Chaves privadas salvas separadamente em data/private/
# ----------------------------------------------------------------------------
def test_private_keys_saved_in_separate_files(dirs):
    private_dir, _ = dirs
    public_keys = generate_authorities(3, GROUP, private_dir)

    assert sorted(p.name for p in private_dir.iterdir()) == [
        "authority_1.key", "authority_2.key", "authority_3.key"
    ]
    xs = []
    for pk in public_keys:
        data = json.loads(key_path(pk.authority_id, private_dir).read_text())
        assert data["authority_id"] == pk.authority_id
        assert data["group"] == {"p": GROUP.p, "q": GROUP.q, "g": GROUP.g}
        assert 2 <= data["x"] <= GROUP.q - 1
        assert data["h"] == pk.h == pow(GROUP.g, data["x"], GROUP.p)
        xs.append(data["x"])
    assert len(set(xs)) == 3, "cada autoridade deve ter sua própria x_i"


@pytest.mark.skipif(os.name != "posix", reason="permissões Unix")
def test_private_key_file_is_owner_only(dirs):
    private_dir, _ = dirs
    Authority.generate("1", GROUP, private_dir)
    assert key_path("1", private_dir).stat().st_mode & 0o777 == 0o600


def test_existing_key_is_not_overwritten(dirs):
    private_dir, _ = dirs
    Authority.generate("1", GROUP, private_dir)
    before = key_path("1", private_dir).read_text()
    with pytest.raises(FileExistsError):
        Authority.generate("1", GROUP, private_dir)
    assert key_path("1", private_dir).read_text() == before


def test_load_roundtrip_and_repr_hides_x(dirs):
    private_dir, _ = dirs
    original = Authority.generate("2", GROUP, private_dir)
    loaded = Authority.load("2", GROUP, private_dir)
    assert loaded.public_key() == original.public_key()
    x = _read_private_x(private_dir, "2")
    assert str(x) not in repr(loaded)
    assert not hasattr(loaded, "x")


def test_load_rejects_wrong_group(dirs):
    private_dir, _ = dirs
    Authority.generate("1", GROUP, private_dir)
    other = SimpleNamespace(p=GROUP.p, q=GROUP.q, g=4)
    with pytest.raises(ValueError):
        Authority.load("1", other, private_dir)


@pytest.mark.parametrize("draw, expected_x", [(0, 2), (GROUP.q - 3, GROUP.q - 1)])
def test_private_key_range_extremes(dirs, draw, expected_x):
    # randbelow(q-2) devolve [0, q-3]; os extremos devem virar x = 2 e x = q-1.
    private_dir, _ = dirs
    with mock.patch.object(authority_mod.secrets, "randbelow", return_value=draw) as rb:
        Authority.generate("1", GROUP, private_dir)
    rb.assert_called_once_with(GROUP.q - 2)
    assert _read_private_x(private_dir, "1") == expected_x


@pytest.mark.parametrize("x", [0, 1, GROUP.q, True])
def test_private_key_outside_range_is_rejected(x):
    with pytest.raises(ValueError):
        Authority("1", GROUP, x)


# ----------------------------------------------------------------------------
# compute_joint_public_key / publish_joint_public_key (unidade)
# ----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "public_data",
    [
        {},
        {"authorities": []},
        {"authorities": [{"authority_id": "1", "public_key": 5}]},          # int, não str
        {"authorities": [{"authority_id": "1", "public_key": "-5"}]},
        {"authorities": [{"authority_id": "1", "public_key": "0x10"}]},
        {"authorities": [{"authority_id": "1", "public_key": "1"}]},
        {"authorities": [{"authority_id": "1", "public_key": str(GROUP.p)}]},
        {"authorities": [{"authority_id": "1", "public_key": "4"},
                         {"authority_id": "1", "public_key": "16"}]},       # id repetido
    ],
)
def test_compute_joint_public_key_rejects_bad_data(public_data):
    # min_authorities=1 isola a validação do formato da regra de quantidade.
    with pytest.raises(JointKeyError):
        compute_joint_public_key(public_data, GROUP, min_authorities=1)


def test_publish_does_not_mutate_input_and_preserves_existing_fields(dirs, registration):
    private_dir, election_path = dirs
    election_path.parent.mkdir(parents=True)
    election_path.write_text(json.dumps({"name": "Eleição teste", "candidates": ["A", "B"]}))

    _register_all(registration, generate_authorities(3, GROUP, private_dir))
    public_data = registration.export_public_data()
    snapshot = json.loads(json.dumps(public_data))

    published = publish_joint_public_key(public_data, GROUP, election_path)

    assert public_data == snapshot
    assert published["name"] == "Eleição teste"
    assert published["candidates"] == ["A", "B"]
    for field in ("schema_version", "election_id", "frozen", "voters", "authorities"):
        assert published[field] == snapshot[field]
    assert json.loads(election_path.read_text()) == published


# ----------------------------------------------------------------------------
# Ponta a ponta: generate -> Registration -> export -> h -> election.json
# ----------------------------------------------------------------------------
@pytest.mark.parametrize("n", [3, 5])
def test_end_to_end_joint_key_equals_g_to_sum_of_private_keys(dirs, registration, n):
    private_dir, election_path = dirs

    public_keys = generate_authorities(n, GROUP, private_dir)
    registered = _register_all(registration, public_keys)
    assert all(isinstance(a, RegisteredAuthority) for a in registered)
    assert [a.public_key for a in registered] == [pk.h for pk in public_keys]

    registration.freeze()
    public_data = registration.export_public_data()
    assert [a["public_key"] for a in public_data["authorities"]] == [str(pk.h) for pk in public_keys]

    published = publish_joint_public_key(public_data, GROUP, election_path)

    xs = [_read_private_x(private_dir, pk.authority_id) for pk in public_keys]
    expected = pow(GROUP.g, sum(xs), GROUP.p)

    on_disk = json.loads(election_path.read_text())
    assert on_disk == published
    assert int(on_disk["joint_public_key"]) == expected
    assert compute_joint_public_key(public_data, GROUP) == expected
    assert on_disk["group"] == {"p": str(GROUP.p), "q": str(GROUP.q), "g": str(GROUP.g)}
    assert on_disk["election_id"] == "eleicao-2026"
    assert on_disk["frozen"] is True


def test_end_to_end_no_private_key_leaks(dirs, registration):
    private_dir, election_path = dirs
    public_keys = generate_authorities(3, GROUP, private_dir)
    _register_all(registration, public_keys)
    public_data = registration.export_public_data()
    publish_joint_public_key(public_data, GROUP, election_path)

    xs = [_read_private_x(private_dir, pk.authority_id) for pk in public_keys]
    secrets_ = {str(x) for x in xs} | {str(sum(xs)), str(sum(xs) % GROUP.q)}

    published_text = election_path.read_text()
    export_text = json.dumps(public_data)
    assert '"x"' not in published_text
    for secret in secrets_:
        assert secret not in published_text
        assert secret not in export_text
        assert secret not in repr(registration.get_authority("1"))

    # Nada além de election.json foi escrito na pasta pública.
    assert [p.name for p in election_path.parent.iterdir()] == ["election.json"]


def test_end_to_end_never_reads_private_dir(dirs, registration, monkeypatch):
    private_dir, election_path = dirs
    public_keys = generate_authorities(3, GROUP, private_dir)
    real_open = open

    def guarded_open(file, *args, **kwargs):
        resolved = Path(file).resolve()
        assert not resolved.is_relative_to(private_dir.resolve()), f"tentou abrir {file}"
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr("builtins.open", guarded_open)
    _register_all(registration, public_keys)
    publish_joint_public_key(registration.export_public_data(), GROUP, election_path)


def test_registration_rejects_duplicate_authority(dirs, registration):
    private_dir, _ = dirs
    pk = generate_authorities(3, GROUP, private_dir)[0]
    registration.register_authority(pk.authority_id, pk.h)
    with pytest.raises(DuplicateParticipantError):
        registration.register_authority(pk.authority_id, pk.h)
    with pytest.raises(DuplicateParticipantError):
        registration.register_authority("2", pk.h)


@pytest.mark.parametrize("bad_h", [1, GROUP.p - 1, GROUP.p, NON_RESIDUE])
def test_registration_rejects_key_outside_subgroup(registration, bad_h):
    with pytest.raises(InvalidPublicKeyError):
        registration.register_authority("1", bad_h)


def test_registration_closed_after_freeze(dirs, registration):
    private_dir, _ = dirs
    pk = generate_authorities(3, GROUP, private_dir)[0]
    registration.freeze()
    with pytest.raises(RegistrationClosedError):
        registration.register_authority(pk.authority_id, pk.h)

