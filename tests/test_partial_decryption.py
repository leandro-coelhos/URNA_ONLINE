"""Testes da decifração conjunta do resultado (Issue #11).

Cobre ``src/authorities/partial_decryption.py``:
- ponta a ponta com 3 e 4 autoridades e 2 candidatos (inclusive total 0);
- falha da apuração quando falta qualquer autoridade;
- limite de cada total = nº de cédulas, não de eleitores (abstenção), e soma
  dos totais = nº de cédulas (detecção agregada, sem a prova 0/1);
- rejeição de parcelas inválidas, não cadastradas, duplicadas, incompletas
  ou fora de ``APURACAO``/sem congelamento;
- ausência de ``x_i``, ``Σ x_i`` e ``w`` em estruturas, arquivos públicos e
  exceções;
- conferência do agregado pela autoridade contra o quadro público antes de
  decifrar (``AggregateVerificationError``).

Módulos reais, sem stubs
------------------------
Nada é substituído em ``sys.modules``.

- Exponenciação modular: o ``pow`` nativo, padrão do projeto.
- ``mod_inv`` e ``discrete_log``: os padrões reais de
  ``combine_and_decrypt_result`` (``src.crypto.group.inverse_mod`` e
  ``src.crypto.elgamal.bounded_discrete_log``). Os oráculos de teste
  (``oracle_mod_inv`` e ``oracle_discrete_log``) servem só para conferir esses
  padrões e para os testes que injetam funções defeituosas.
- Cifras com ``encrypt_bit`` e agregado com ``build_aggregate``
  (``src.crypto.homomorphic.aggregate_ciphertexts``).
- Quadro público REAL no formato de ``src.bulletin_board.hash_chain``: cada
  cédula é assinada com ``sign_ballot`` (chaves RSA de 3072 bits, padrão de
  ``generate_signing_key``) e gravada com ``make_record``/``encode_record``,
  os mesmos bytes que ``BulletinBoard.append`` grava, só que sem o ``flock``.
  Assim este arquivo continua sem depender de ``fcntl``; o ``BulletinBoard``
  com trava é exercitado em ``tests/security/`` (cenário compartilhado).

O teste faz o papel do cliente do eleitor e de cada autoridade (objetos
``Authority`` locais).
"""

import builtins
import copy
import dataclasses
import json
import re
import secrets
import shutil
import sys
import traceback
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
from src.authorities.authority import (  # noqa: E402
    Authority,
    key_path,
    publish_joint_public_key,
)
from src.bulletin_board.hash_chain import (  # noqa: E402
    encode_record,
    genesis_hash,
    hash_record,
    make_checkpoint,
    make_record,
)
from src.crypto.ballots import sign_ballot  # noqa: E402
from src.crypto.elgamal import encrypt_bit  # noqa: E402
from src.crypto.group import inverse_mod  # noqa: E402
from src.crypto.keys import public_key_to_pem  # noqa: E402
from src.crypto.signatures import generate_signing_key  # noqa: E402
from src.authorities.partial_decryption import (  # noqa: E402
    AggregateVerificationError,
    AuthorityPartialSubmission,
    CandidatePartialShare,
    DecryptionError,
    DuplicateShareError,
    InconsistentTotalsError,
    InvalidShareError,
    MissingAuthorityShareError,
    PartialDecryptionCollector,
    PartialDecryptionError,
    TallyStateError,
    UnregisteredAuthorityError,
    build_aggregate,
    combine_and_decrypt_result,
    crypto_discrete_log,
    publish_aggregate,
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
# =============================================================================
# Quadro público real (formato de src.bulletin_board.hash_chain, sem fcntl)
# =============================================================================
BOARD_FILE = "bulletin_board.jsonl"
MAX_VOTERS = 6  # 5 cédulas (DEFAULT_CHOICES) + 1 eleitor que se abstém


@pytest.fixture(scope="module")
def voter_keys():
    """Chaves RSA dos eleitores (3072 bits): geradas UMA vez por módulo."""
    return [generate_signing_key() for _ in range(MAX_VOTERS)]


def voter_id(position: int) -> str:
    return f"eleitor-{position + 1}"


def signed_envelope(position: int, key, pairs, *, election_id: str = ELECTION_ID) -> dict:
    """Cliente do eleitor: cédula com um par ``(c1, c2)`` por candidato, assinada."""
    body = {
        "schema_version": 1,
        "election_id": election_id,
        "voter_id": voter_id(position),
        "ciphertexts": [{"candidate_id": cid, "c1": str(c1), "c2": str(c2)}
                        for cid, (c1, c2) in zip(CANDIDATES, pairs)],
    }
    return sign_ballot(body, key)


def write_board(path: Path, envelopes) -> list:
    """Grava o quadro com ``make_record``/``encode_record`` (cadeia real).

    Devolve os registros gravados, na ordem.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    records, previous = [], genesis_hash(ELECTION_ID)
    with open(path, "wb") as fh:
        for index, envelope in enumerate(envelopes):
            record = make_record(envelope, index=index, previous_hash=previous)
            fh.write(encode_record(record))
            records.append(record)
            previous = record["hash"]
    return records


def write_raw_board(path: Path, records) -> None:
    """Grava registros já montados (inclusive adulterados), uma linha JSON cada."""
    path.write_text("".join(
        json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
        for r in records
    ), encoding="utf-8")


def rechain(records) -> list:
    """Recalcula index, previous_hash e hash: o que qualquer um consegue fazer."""
    chained, previous = [], genesis_hash(ELECTION_ID)
    for index, record in enumerate(records):
        body = {k: v for k, v in record.items() if k not in ("hash", "index", "previous_hash")}
        body.update(index=index, previous_hash=previous)
        chained.append({**body, "hash": hash_record(body)})
        previous = chained[-1]["hash"]
    return chained


@dataclasses.dataclass
class Env:
    authorities: list
    election_data: dict
    aggregate_data: dict
    expected: dict
    randomness: list
    private_dir: Path
    public_dir: Path
    voter_keys: list
    ballots: list  # pares (c1, c2) de cada cédula do quadro, na ordem
    envelopes: list

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
    def board_path(self) -> Path:
        return self.public_dir / BOARD_FILE

    def records(self) -> list:
        return [json.loads(line) for line in self.board_path.read_text().splitlines()]

    @property
    def ids(self) -> list:
        return [a.authority_id for a in self.authorities]

    def private_xs(self) -> list:
        # O teste lê os arquivos privados como oráculo; o código testado nunca.
        return [json.loads(key_path(i, self.private_dir).read_text())["x"] for i in self.ids]

    def partial(self, authority, **kwargs) -> AuthorityPartialSubmission:
        kwargs.setdefault("election_state", APURACAO)
        kwargs.setdefault("board_path", self.board_path)
        aggregate_data = kwargs.pop("aggregate_data", self.aggregate_data)
        election_data = kwargs.pop("election_data", self.election_data)
        return compute_authority_partials(authority, election_data, aggregate_data, **kwargs)

    def all_partials(self) -> list:
        return [self.partial(a) for a in self.authorities]

    def collector(self, **kwargs) -> PartialDecryptionCollector:
        kwargs.setdefault("election_state", APURACAO)
        election_data = kwargs.pop("election_data", self.election_data)
        return PartialDecryptionCollector(
            election_data, self.aggregate_data, **kwargs
        )

    def combine(self, submissions, **kwargs) -> dict:
        kwargs.setdefault("election_state", APURACAO)
        election_data = kwargs.pop("election_data", self.election_data)
        return combine_and_decrypt_result(
            election_data,
            self.aggregate_data,
            submissions,
            result_path=self.result_path,
            **kwargs,  # mod_inv/discrete_log: padrões reais, salvo injeção explícita
        )


DEFAULT_CHOICES = ("Alice", "Bob", "Alice", "Bob", "Alice")


def _build_honest(root, voter_keys, *, n_authorities=3, choices=DEFAULT_CHOICES) -> Env:
    """Monta o cenário honesto em ``root/data`` (feito UMA vez por módulo e por cenário).

    Os testes não usam este diretório diretamente: ``_build`` copia os
    arquivos para o ``tmp_path`` de cada teste.
    """
    private_dir = root / "data" / "private"
    public_dir = root / "data" / "public"

    # Cada autoridade gera a própria chave; o arquivo fica em data/private/.
    authorities = [
        Authority.generate(str(i), GROUP, private_dir) for i in range(1, n_authorities + 1)
    ]

    # Um eleitor a mais que as cédulas (abstenção): o limite dos totais é o
    # nº de cédulas (ballot_count do agregado), não o nº de eleitores.
    n_voters = len(choices) + 1
    keys = voter_keys[:n_voters]
    public_data = {
        "schema_version": 1,
        "election_id": ELECTION_ID,
        "frozen": True,
        "candidates": CANDIDATES,
        "voters": [
            {"voter_id": voter_id(i), "public_key": public_key_to_pem(key.public_key())}
            for i, key in enumerate(keys)
        ],
        "authorities": [
            {"authority_id": a.authority_id, "public_key": str(a.public_key().h)}
            for a in authorities
        ],
    }
    publish_joint_public_key(public_data, GROUP, public_dir / "election.json")
    election_data = load_public_json(public_dir / "election.json")
    h = int(election_data["joint_public_key"])

    # Cliente do eleitor (encrypt_bit real) + agregação homomórfica real.
    randomness = []
    ballots = []
    for choice in choices:
        pairs = []
        for cid in CANDIDATES:
            ciphertext, r = encrypt_bit(1 if choice == cid else 0, h, GROUP)
            randomness.append(r)
            pairs.append((ciphertext.a, ciphertext.b))
        ballots.append(pairs)
    # Cada cédula assinada pelo seu eleitor e publicada no quadro, em ordem.
    envelopes = [signed_envelope(i, keys[i], pairs) for i, pairs in enumerate(ballots)]
    write_board(public_dir / BOARD_FILE, envelopes)
    publish_aggregate(ELECTION_ID, CANDIDATES, ballots, GROUP,
                      aggregate_path=public_dir / "aggregate_ciphertexts.json")
    aggregate_data = load_public_json(public_dir / "aggregate_ciphertexts.json")
    # Oráculo: o produto publicado é o produto das cifras.
    for position, cid in enumerate(CANDIDATES):
        c1 = c2 = 1
        for pairs in ballots:
            c1, c2 = c1 * pairs[position][0] % P, c2 * pairs[position][1] % P
        assert aggregate_data["ciphertexts"][cid] == {"c1": str(c1), "c2": str(c2)}

    expected = {cid: choices.count(cid) for cid in CANDIDATES}
    return Env(authorities, election_data, aggregate_data, expected, randomness,
               private_dir, public_dir, list(keys), ballots, envelopes)


@pytest.fixture(scope="module")
def honest_scenarios(tmp_path_factory, voter_keys):
    """Cenários honestos do módulo, um por (nº de autoridades, cédulas).

    Montar o cenário (chaves das autoridades, cifras, cédulas assinadas,
    quadro e agregado) custava ~0,5 s por teste; agora é feito uma vez por
    combinação. Cada teste recebe uma CÓPIA dos arquivos (``_build``).
    """
    built = {}

    def get(n_authorities: int, choices) -> Env:
        key = (n_authorities, tuple(choices))
        if key not in built:
            root = tmp_path_factory.mktemp("cenario-honesto")
            built[key] = _build_honest(root, voter_keys, n_authorities=n_authorities,
                                       choices=tuple(choices))
        return built[key]

    return get


def _build(tmp_path, honest_scenarios, *, n_authorities=3, choices=DEFAULT_CHOICES) -> Env:
    """Cópia do cenário honesto em ``tmp_path/data``, só deste teste.

    Arquivos (``data/public`` e ``data/private``), dicionários lidos desses
    arquivos, objetos ``Authority`` (carregados da cópia de ``data/private``)
    e listas são novos: um teste que adultera dados mexe só na própria cópia.
    """
    template = honest_scenarios(n_authorities, choices)
    shutil.copytree(template.public_dir.parent, tmp_path / "data")
    private_dir = tmp_path / "data" / "private"
    public_dir = tmp_path / "data" / "public"
    authorities = [Authority.load(a.authority_id, GROUP, private_dir) for a in template.authorities]
    return Env(
        authorities,
        load_public_json(public_dir / "election.json"),
        load_public_json(public_dir / "aggregate_ciphertexts.json"),
        dict(template.expected),
        list(template.randomness),
        private_dir,
        public_dir,
        list(template.voter_keys),
        copy.deepcopy(template.ballots),
        copy.deepcopy(template.envelopes),
    )


@pytest.fixture
def env(tmp_path, honest_scenarios):
    return _build(tmp_path, honest_scenarios)


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


def test_real_crypto_defaults_agree_with_oracles():
    # Padrões de combine_and_decrypt_result: inverse_mod e bounded_discrete_log.
    assert pd_mod._default_mod_inv is inverse_mod
    assert inverse_mod(16, P) == oracle_mod_inv(16, P)
    discrete_log = crypto_discrete_log(Q)
    for target, max_exp in ((pow(G, 7, P), 10), (1, 10), (pow(G, 11, P), 10), (pow(G, 3, P), 3)):
        assert discrete_log(target, G, P, max_exp) == oracle_discrete_log(target, G, P, max_exp)


def test_build_aggregate_validates_input():
    with pytest.raises(PartialDecryptionError, match="não há cédulas"):
        build_aggregate(ELECTION_ID, CANDIDATES, [], GROUP)
    with pytest.raises(PartialDecryptionError, match="esperadas 2 cifras"):
        build_aggregate(ELECTION_ID, CANDIDATES, [[(4, 4)]], GROUP)
    with pytest.raises(PartialDecryptionError, match="distintos"):
        build_aggregate(ELECTION_ID, ["Alice", "Alice"], [[(4, 4), (16, 16)]], GROUP)


@pytest.mark.parametrize("stage", ["CADASTRO", "VOTACAO_ABERTA", "ENCERRADA"])
def test_publish_aggregate_only_in_apuracao(tmp_path, stage):
    path = tmp_path / "aggregate_ciphertexts.json"
    with pytest.raises(TallyStateError, match=f"etapa atual: {stage}"):
        publish_aggregate(ELECTION_ID, CANDIDATES, [[(4, 4), (16, 16)]], GROUP,
                          election_state=stage, aggregate_path=path)
    assert not path.exists()


# =============================================================================
# 1. Fluxo ponta a ponta
# =============================================================================
@pytest.mark.parametrize("n_authorities", [3, 4])
@pytest.mark.parametrize(
    "choices",
    [DEFAULT_CHOICES, ("Alice", "Alice", "Alice")],
    ids=["3x2", "bob-zero"],
)
def test_end_to_end(tmp_path, honest_scenarios, n_authorities, choices):
    env = _build(tmp_path, honest_scenarios, n_authorities=n_authorities, choices=choices)

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
        election_state=APURACAO,
    )
    assert reloaded.submissions == collector.submissions

    # Combinação de todas as parcelas e result.json.
    result = env.combine(reloaded)
    assert result["totals"] == env.expected
    assert result["election_id"] == ELECTION_ID
    assert result["authorities"] == env.ids
    # Limite = nº de cédulas (critério do auditor), mesmo com um eleitor a mais.
    assert result["max_votes"] == len(choices) == env.aggregate_data["ballot_count"]
    assert len(env.election_data["voters"]) == len(choices) + 1
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
                              election_state=APURACAO)
    with pytest.raises(InvalidShareError):
        verify_authority_partials(
            _tamper(submission, "Alice", s=(submission.share_for("Alice").s + 1) % Q),
            env.election_data, env.aggregate_data,
        )


def test_submission_roundtrip_through_dict(env):
    submission = env.partial(env.authorities[0])
    assert AuthorityPartialSubmission.from_dict(submission.to_dict()) == submission


# =============================================================================
# 2. Apuração sem uma autoridade falha
# =============================================================================
@pytest.mark.security
@pytest.mark.parametrize("n_authorities", [3, 4])
def test_missing_one_authority_fails(tmp_path, honest_scenarios, n_authorities):
    env = _build(tmp_path, honest_scenarios, n_authorities=n_authorities)
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


@pytest.mark.security
def test_missing_authority_even_with_three_or_more_present(tmp_path, honest_scenarios):
    # 4 cadastradas, 3 enviadas: o mínimo (3) não basta, é preciso TODAS.
    env = _build(tmp_path, honest_scenarios, n_authorities=4)
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
@pytest.mark.security
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


@pytest.mark.security
def test_proof_with_other_authority_key_rejected(env):
    # Autoridade 2 tenta se passar pela 1 reaproveitando as próprias parcelas.
    submission_2 = env.partial(env.authorities[1])
    impostor = AuthorityPartialSubmission(env.ids[0], submission_2.shares)
    with pytest.raises(InvalidShareError):
        env.collector().submit(impostor)


@pytest.mark.security
def test_valid_proof_for_unregistered_key_rejected(env):
    # Prova internamente coerente, mas feita com outra chave privada: o
    # servidor verifica contra o h_1 de election.json e recusa.
    ctx = pd_mod._parse_election(env.election_data)
    aggregate = pd_mod._parse_aggregate(env.aggregate_data, ctx)
    impostor = Authority(env.ids[0], GROUP, 2 + secrets.randbelow(Q - 2))
    shares = tuple(
        pd_mod._prove_share(impostor, ctx, cid, aggregate[cid][0], impostor.public_key().h)
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
@pytest.mark.security
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
                                   board_path=env.board_path, election_state=APURACAO)
    with pytest.raises(TallyStateError):
        env.collector(election_data=unfrozen)
    with pytest.raises(TallyStateError):
        env.combine(env.all_partials(), election_data=unfrozen)
    assert not env.result_path.exists()


def test_tally_state_error_is_partial_decryption_error():
    for exc in (TallyStateError, UnregisteredAuthorityError, DuplicateShareError,
                InvalidShareError, MissingAuthorityShareError, DecryptionError,
                InconsistentTotalsError):
        assert issubclass(exc, PartialDecryptionError)
    # Quem já trata DecryptionError (total irrecuperável) também trata a soma.
    assert issubclass(InconsistentTotalsError, DecryptionError)


# --- dados públicos de entrada --------------------------------------------------
@pytest.mark.parametrize("bad", [True, 1, "1", P - 1, NON_RESIDUE, "abc", "0012"],
                         ids=["bool", "um-int", "um-str", "p-1", "nao-residuo", "texto", "zeros"])
def test_malformed_aggregate_c1_rejected(env, bad):
    aggregate = json.loads(json.dumps(env.aggregate_data))
    aggregate["ciphertexts"]["Alice"]["c1"] = bad
    with pytest.raises(PartialDecryptionError):
        compute_authority_partials(env.authorities[0], env.election_data, aggregate,
                                   board_path=env.board_path, election_state=APURACAO)
    with pytest.raises(PartialDecryptionError):
        PartialDecryptionCollector(env.election_data, aggregate)


@pytest.mark.parametrize("bad", [True, P - 1, NON_RESIDUE])
def test_malformed_aggregate_c2_rejected_before_combining(env, bad):
    partials = env.all_partials()
    aggregate = json.loads(json.dumps(env.aggregate_data))
    aggregate["ciphertexts"]["Bob"]["c2"] = bad
    with pytest.raises(PartialDecryptionError):
        combine_and_decrypt_result(env.election_data, aggregate, partials,
                                   result_path=env.result_path)
    assert not env.result_path.exists()


def test_aggregate_from_other_election_rejected(env):
    aggregate = dict(env.aggregate_data, election_id="outra-eleicao")
    with pytest.raises(PartialDecryptionError, match="outra eleição"):
        compute_authority_partials(env.authorities[0], env.election_data, aggregate,
                                   board_path=env.board_path)


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
                                        env.partials_path)


# --- falhas na recuperação do total ---------------------------------------------
@pytest.mark.security
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


# --- limite dos totais = nº de cédulas (mesmo critério do auditor) --------------
def _raw_encrypt(m: int, h: int) -> tuple[int, int]:
    """(g^r, g^m · h^r): o que um eleitor malicioso faz com ``pow`` (m fora de {0, 1})."""
    r = 2 + secrets.randbelow(Q - 2)
    return pow(G, r, P), pow(G, m, P) * pow(h, r, P) % P


def _combine_vectors(env, vectors, **kwargs) -> dict:
    """Apura cédulas arbitrárias (um ``m`` por candidato) na eleição de ``env``.

    Mesma eleição (6 eleitores cadastrados) e mesmas autoridades. Cada cédula
    é assinada por um eleitor cadastrado (o malicioso contorna o cliente, não
    a assinatura) e publicada num quadro próprio, que as autoridades leem e
    conferem antes de decifrar. Parcelas e provas são as reais.
    """
    h = int(env.election_data["joint_public_key"])
    ballots = [[_raw_encrypt(m, h) for m in vector] for vector in vectors]
    board_path = env.public_dir / "vetores" / BOARD_FILE
    write_board(board_path, [signed_envelope(i, env.voter_keys[i], pairs)
                             for i, pairs in enumerate(ballots)])
    aggregate = build_aggregate(ELECTION_ID, CANDIDATES, ballots, GROUP)
    partials = [
        compute_authority_partials(a, env.election_data, aggregate,
                                   board_path=board_path, election_state=APURACAO)
        for a in env.authorities
    ]
    return combine_and_decrypt_result(
        env.election_data, aggregate, partials,
        election_state=APURACAO, result_path=env.result_path, **kwargs,
    )


@pytest.mark.security
def test_abstention_limits_totals_by_ballots_not_registered_voters(env):
    """Abstenção: 6 eleitores cadastrados e 1 cédula, que cifra 3 para Alice.

    Antes o limite era o nº de eleitores ([0, 6]) e Alice 3 era publicado;
    agora é o nº de cédulas ([0, 1]), o mesmo do auditor.
    """
    assert len(env.election_data["voters"]) == 6
    with pytest.raises(DecryptionError, match=r"total de 'Alice' fora de \[0, 1\]"):
        _combine_vectors(env, [(3, 0)])
    assert not env.result_path.exists()


def test_abstention_honest_ballots_are_published_with_ballot_limit(env):
    # 2 cédulas honestas para 6 eleitores: publica com max_votes = 2.
    result = _combine_vectors(env, [(1, 0), (0, 1)])
    assert result["totals"] == {"Alice": 1, "Bob": 1}
    assert result["max_votes"] == 2


def test_explicit_max_votes_above_ballot_count_rejected(env):
    # 5 cédulas: um limite de 6 (nº de eleitores) seria mais frouxo que o do auditor.
    with pytest.raises(PartialDecryptionError, match=r"max_votes \(6\) maior que o número de cédulas \(5\)"):
        env.combine(env.all_partials(), max_votes=6)
    assert not env.result_path.exists()


@pytest.mark.parametrize(
    "change, message",
    [
        ({"ballot_count": None}, "sem ballot_count"),
        ({"ballot_count": 0}, ">= 1"),
        ({"ballot_count": True}, "ballot_count deve ser inteiro"),
        ({"ballot_count": 7}, r"ballot_count \(7\) maior que o número de eleitores cadastrados \(6\)"),
    ],
    ids=["ausente", "zero", "bool", "mais-que-eleitores"],
)
def test_invalid_ballot_count_in_aggregate_rejected(env, change, message):
    partials = env.all_partials()
    aggregate = json.loads(json.dumps(env.aggregate_data))
    aggregate.update(change)
    if aggregate["ballot_count"] is None:
        del aggregate["ballot_count"]
    with pytest.raises(PartialDecryptionError, match=message):
        combine_and_decrypt_result(env.election_data, aggregate, partials,
                                   election_state=APURACAO, result_path=env.result_path)
    assert not env.result_path.exists()


# --- soma dos totais = nº de cédulas (mitigação PARCIAL da falta da prova 0/1) ---
# Detecção AGREGADA: a apuração sabe que alguma cédula não soma 1, mas não
# qual nem de que eleitor. Cédulas que somam 1 com m fora de {0, 1} passam.
@pytest.mark.security
@pytest.mark.parametrize(
    "vectors, totals",
    [
        ([(1, 1), (0, 1), (1, 0)], {"Alice": 2, "Bob": 2}),  # 1 para os dois candidatos
        ([(2, 0), (0, 1), (1, 0)], {"Alice": 3, "Bob": 1}),  # m = 2
        ([(0, 0), (0, 1), (1, 0)], {"Alice": 1, "Bob": 1}),  # cédula toda 0 (não há voto em branco)
    ],
    ids=["1-para-os-dois", "m=2", "tudo-zero"],
)
def test_totals_not_summing_to_ballot_count_publish_nothing(env, vectors, totals):
    # Cada total está em [0, 3]; só a soma denuncia a cédula irregular.
    assert all(0 <= t <= len(vectors) for t in totals.values())
    expected = (f"soma dos totais ({sum(totals.values())}) difere do número de "
                f"cédulas ({len(vectors)})")
    with pytest.raises(InconsistentTotalsError, match=re.escape(expected)) as info:
        _combine_vectors(env, vectors)
    message = str(info.value)
    assert "detecção agregada" in message and "não identifica o eleitor" in message
    assert not any(f"eleitor-{i}" in message for i in range(1, 7))
    assert not env.result_path.exists()


@pytest.mark.security
def test_ballot_keeping_sum_one_is_still_undetected_without_bit_proof(env):
    """LIMITAÇÃO: (-1, +2) soma 1, como uma cédula honesta; a soma não a pega.

    Alice perde um voto e Bob ganha dois; só a prova 0/1 por cifra detectaria.
    """
    result = _combine_vectors(env, [(-1, 2), (1, 0), (0, 1)])
    assert result["totals"] == {"Alice": 0, "Bob": 3}
    assert sum(result["totals"].values()) == 3


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
    # O quadro público (lido pelas autoridades) também é varrido.
    assert names == ["aggregate_ciphertexts.json", "authority_partials.json",
                     BOARD_FILE, "election.json", "result.json"]
    for path in env.public_dir.iterdir():
        text = path.read_text(encoding="utf-8")
        assert '"x"' not in text
        for secret in secret_values:
            assert secret not in text, f"segredo vazou em {path.name}"

    # Memória do servidor (coletor) também só com dados públicos.
    collector_repr = repr(vars(collector)) + json.dumps(collector.to_dict())
    for secret in secret_values:
        assert secret not in collector_repr


def test_local_failure_does_not_leak_secret_in_exception(env, monkeypatch):
    authority = env.authorities[0]
    x = env.private_xs()[0]

    def leaky_pow(base, exponent, modulus):
        if exponent == x:
            raise RuntimeError(f"falha interna com expoente {exponent}")
        return builtins.pow(base, exponent, modulus)

    # Falha simulada no cálculo local: o pow visto pelo módulo passa a lançar
    # uma exceção cuja mensagem contém x_i.
    monkeypatch.setattr(pd_mod, "pow", leaky_pow, raising=False)
    with pytest.raises(PartialDecryptionError) as info:
        compute_authority_partials(authority, env.election_data, env.aggregate_data,
                                   board_path=env.board_path, election_state=APURACAO)
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


# =============================================================================
# 5. Conferência do agregado pela autoridade (quadro público)
# =============================================================================
# Os ataques com o quadro real travado (BulletinBoard) estão no cenário 8 de
# tests/security/test_attacks.py; aqui ficam os casos de unidade.
def test_aggregate_verification_error_is_partial_decryption_error():
    # Quem já trata PartialDecryptionError continua tratando a recusa.
    assert issubclass(AggregateVerificationError, PartialDecryptionError)


def test_board_path_is_required(env):
    with pytest.raises(TypeError, match="board_path"):
        compute_authority_partials(env.authorities[0], env.election_data, env.aggregate_data,
                                   election_state=APURACAO)


@pytest.mark.security
def test_single_ballot_refused_before_private_key_is_used(env, monkeypatch):
    """A recusa acontece ANTES de qualquer uso de x_i: nenhuma parcela é calculada."""
    def must_not_run(*args, **kwargs):
        raise AssertionError("x_i usado com um agregado não conferido")

    monkeypatch.setattr(pd_mod, "_prove_share", must_not_run)
    forged = build_aggregate(ELECTION_ID, CANDIDATES, [env.ballots[0]], GROUP)
    with pytest.raises(AggregateVerificationError,
                       match=r"ballot_count informado 1, esperado 5; C1 e C2 de 'Alice'"):
        env.partial(env.authorities[0], aggregate_data=forged)


def test_empty_board_refused(env):
    env.board_path.write_bytes(b"")
    with pytest.raises(AggregateVerificationError, match="quadro público vazio"):
        env.partial(env.authorities[0])


def test_missing_board_file_refused(env, tmp_path):
    with pytest.raises(AggregateVerificationError, match=r"quadro público ilegível \(nao_existe\.jsonl"):
        env.partial(env.authorities[0], board_path=tmp_path / "nao_existe.jsonl")


def test_malformed_board_line_refused(env):
    env.board_path.write_bytes(env.board_path.read_bytes() + b"isto nao e json\n")
    with pytest.raises(AggregateVerificationError,
                       match=r"quadro público inválido \(BoardFormatError: "):
        env.partial(env.authorities[0])


def test_election_without_candidates_refused(env):
    election = {k: v for k, v in env.election_data.items() if k != "candidates"}
    with pytest.raises(AggregateVerificationError, match="sem a lista de candidatos"):
        env.partial(env.authorities[0], election_data=election)


def test_election_without_voters_refused(env):
    election = {k: v for k, v in env.election_data.items() if k != "voters"}
    with pytest.raises(AggregateVerificationError, match="sem o cadastro de eleitores"):
        env.partial(env.authorities[0], election_data=election)


def test_board_with_unregistered_voter_refused(env):
    # election.json sem o eleitor-1, que tem cédula no quadro.
    election = dict(env.election_data,
                    voters=[v for v in env.election_data["voters"] if v["voter_id"] != voter_id(0)])
    with pytest.raises(AggregateVerificationError,
                       match=r"quadro público inválido \(IneligibleVoterError: "):
        env.partial(env.authorities[0], election_data=election)


def test_ballot_count_must_be_an_integer(env):
    aggregate = dict(env.aggregate_data, ballot_count=True)
    with pytest.raises(AggregateVerificationError, match="ballot_count deve ser inteiro"):
        env.partial(env.authorities[0], aggregate_data=aggregate)


def test_truncated_board_refused_only_with_independent_checkpoint(env):
    """Sem checkpoint, o quadro truncado + agregado coerente passa (limitação);
    com o checkpoint do quadro original, é recusado."""
    original = make_checkpoint(election_id=ELECTION_ID, size=len(env.ballots),
                               head_hash=env.records()[-1]["hash"])
    write_board(env.board_path, env.envelopes[:-1])
    truncated = build_aggregate(ELECTION_ID, CANDIDATES, env.ballots[:-1], GROUP)
    env.partial(env.authorities[0], aggregate_data=truncated)  # aceito: limitação assumida
    with pytest.raises(AggregateVerificationError,
                       match=r"ChainIntegrityError: Quadro diverge do tamanho ou hash"):
        env.partial(env.authorities[0], aggregate_data=truncated, expected_checkpoint=original)


def test_state_is_checked_before_reading_the_board(env, tmp_path):
    with pytest.raises(TallyStateError):
        env.partial(env.authorities[0], election_state=ElectionState.ENCERRADA,
                    board_path=tmp_path / "nao_existe.jsonl")


def test_authorities_import_only_board_tally_from_the_auditor():
    """As autoridades reaproveitam src.auditor.board_tally, nunca a classe Auditor.

    E board_tally fica em src/auditor/: o teste AST do auditor
    (tests/auditor/test_auditor.py) percorre src/auditor/*.py e exige que ele
    importe só src.crypto e src.bulletin_board.
    """
    import ast

    tally = ROOT / "src" / "auditor" / "board_tally.py"
    assert tally in set((ROOT / "src" / "auditor").glob("*.py"))
    for source in (ROOT / "src" / "authorities").glob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("src.auditor"):
                assert node.module == "src.auditor.board_tally", source.name
                assert "Auditor" not in {alias.name for alias in node.names}
            elif isinstance(node, ast.Import):
                assert not any(a.name.startswith("src.auditor") for a in node.names), source.name
    for node in ast.walk(ast.parse(tally.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and (node.level or (node.module or "").startswith("src")):
            assert node.level == 0 and node.module.startswith(("src.crypto", "src.bulletin_board"))