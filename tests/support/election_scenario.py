"""Eleição completa de teste, compartilhada pelo auditor e pela suíte de segurança.

Este módulo saiu de ``tests/auditor/test_auditor.py`` (Item 4) para que a
suíte de segurança (T14, ``tests/security/``) reutilize o MESMO cenário em vez
de montar outro. Os fixtures que o usam ficam em ``tests/conftest.py``.

Cenário
-------
A eleição é montada SÓ com os módulos reais do repositório, sem stubs nem
substituições em ``sys.modules``:

- ``src.crypto``: grupo RFC 3526 (``DEFAULT_PARAMETERS``), chaves RSA
  (``generate_signing_key``), cifragem ElGamal (``encrypt_bit``) e o envelope
  assinado da cédula (``src.crypto.ballots.sign_ballot``);
- ``Registration`` (cadastro), ``Election``/``VotingService`` (votação);
- ``src.bulletin_board.board.BulletinBoard`` como quadro público, ligado ao
  serviço por ``board_publisher_for`` (o quadro reverifica cada assinatura);
- ``Authority`` (chaves em ``data/private/``) e ``partial_decryption``
  (agregado, parcelas, provas e ``result.json``, com ``inverse_mod`` e
  ``bounded_discrete_log`` reais).

São 3 eleitores, 3 autoridades e 2 candidatos; com os votos padrão o
resultado é Alice 2 x 1 Bob. ``build_election`` aceita vetores de votos
arbitrários (inclusive valores fora de {0, 1}, para simular um eleitor
malicioso que não usa o cliente honesto) e pode parar em qualquer etapa
anterior à apuração.

Prova 0/1 (ZKP): o envelope de ``src.crypto.ballots`` não tem campo para
ela; ``ballot_with_bit_proofs`` documenta essa limitação (ver os testes
``xfail`` estritos).
"""

from __future__ import annotations

import dataclasses
import json
import secrets
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.auditor.auditor import AuditReport, Auditor  # noqa: E402
from src.authorities.authority import Authority, publish_joint_public_key  # noqa: E402
from src.authorities.partial_decryption import (  # noqa: E402
    PartialDecryptionCollector,
    combine_and_decrypt_result,
    compute_authority_partials,
    load_public_json,
    publish_aggregate,
)
from src.bulletin_board.board import BulletinBoard  # noqa: E402
from src.bulletin_board.hash_chain import genesis_hash, hash_record  # noqa: E402
from src.crypto.ballots import sign_ballot  # noqa: E402
from src.crypto.bit_proof import prove_bit  # noqa: E402
from src.crypto.elgamal import encrypt_bit  # noqa: E402
from src.crypto.group import DEFAULT_PARAMETERS  # noqa: E402
from src.crypto.keys import public_key_to_pem  # noqa: E402
from src.crypto.signatures import generate_signing_key  # noqa: E402
from src.election.election import Election  # noqa: E402
from src.server.registration import Registration  # noqa: E402
from src.server.voting import VotingService, board_publisher_for  # noqa: E402

# =============================================================================
# Grupo e constantes
# =============================================================================
GROUP = DEFAULT_PARAMETERS  # RFC 3526 MODP 14: p de 2048 bits, q = (p-1)/2, g = 2
P, Q, G = GROUP.p, GROUP.q, GROUP.g

ELECTION_ID = "eleicao-2026"
CANDIDATES = ["Alice", "Bob"]
VOTES = {"eleitor-1": "Alice", "eleitor-2": "Bob", "eleitor-3": "Alice"}
EXPECTED_TOTALS = {"Alice": 2, "Bob": 1}
N_AUTHORITIES = 3
BOARD_FILE = "bulletin_board.jsonl"

# Etapas em que build_election pode parar (a última publica o resultado).
STOP_STATES = ("CADASTRO", "VOTACAO_ABERTA", "ENCERRADA", "APURACAO")


# =============================================================================
# Eleitor (cliente): RSA real, cifragem ElGamal exponencial e envelope assinado
# =============================================================================
def _new_rsa_key():
    return generate_signing_key(2048)


def _public_pem(private) -> str:
    return public_key_to_pem(private.public_key())


def _encrypt(m: int, h: int) -> tuple:
    """(c1, c2) = (g^r, g^m · h^r mod p).

    Para m em {0, 1}, usa o ``encrypt_bit`` real de ``src.crypto.elgamal``
    (o que o cliente honesto faz). Para outros valores, ``encrypt_bit`` recusa:
    aqui a conta é feita com ``pow``, exatamente o que um eleitor malicioso
    que contorna o cliente consegue fazer (``pow`` aceita ``m`` negativo:
    ``g^-1`` = inverso de ``g`` módulo ``p``).
    """
    if m in (0, 1):
        ciphertext, _ = encrypt_bit(m, h, GROUP)
        return (ciphertext.a, ciphertext.b)
    r = 2 + secrets.randbelow(Q - 2)
    return (pow(G, r, P), pow(G, m, P) * pow(h, r, P) % P)


def _choice_vector(candidate: str) -> tuple:
    return tuple(1 if c == candidate else 0 for c in CANDIDATES)


def ballot_body(voter_id: str, pairs: Sequence[tuple], *, election_id: str = ELECTION_ID,
                candidates: Sequence[str] = CANDIDATES) -> dict:
    """Cédula no formato de ``src.crypto.ballots`` (ainda sem assinatura)."""
    return {
        "schema_version": 1,
        "election_id": election_id,
        "voter_id": voter_id,
        "ciphertexts": [
            {"candidate_id": cid, "c1": str(c1), "c2": str(c2)}
            for cid, (c1, c2) in zip(candidates, pairs)
        ],
    }


def signed_ballot(voter_id: str, private, pairs: Sequence[tuple]) -> dict:
    """Monta e assina (``sign_ballot`` real) um envelope a partir das cifras."""
    return sign_ballot(ballot_body(voter_id, [tuple(p) for p in pairs]), private)


def encrypted_ballot(voter_id: str, private, vector: Sequence[int], h: int) -> dict:
    """Cifra cada ``m`` de ``vector`` (um por candidato) e assina o envelope."""
    return signed_ballot(voter_id, private, [_encrypt(m, h) for m in vector])


def _ballot(voter_id: str, private, candidate: str, h: int) -> dict:
    return encrypted_ballot(voter_id, private, _choice_vector(candidate), h)


def ballot_with_bit_proofs(voter_id: str, private, vector: Sequence[int], h: int) -> dict:
    """Tenta montar um envelope com provas 0/1 REAIS (``src.crypto.bit_proof``).

    LIMITAÇÃO ATUAL: o envelope de ``src.crypto.ballots`` não tem campo para a
    prova, então ``sign_ballot`` lança ``BallotFormatError``. Os testes que
    usam esta função são ``xfail(strict=True, raises=BallotFormatError)``:
    quando a prova entrar no formato, eles passam a executar o cenário
    completo e o ``xfail`` estrito obriga a atualizá-los.
    """
    pairs, proofs = [], []
    for m in vector:
        ciphertext, r = encrypt_bit(m, h, GROUP)
        pairs.append((ciphertext.a, ciphertext.b))
        proofs.append(dataclasses.asdict(prove_bit(ciphertext, h, r, m, GROUP)))
    body = ballot_body(voter_id, pairs)
    body["proof"] = [{k: str(v) for k, v in proof.items()} for proof in proofs]
    return sign_ballot(body, private)


# =============================================================================
# Quadro público real (src.bulletin_board): leitura e adulteração pelo "atacante"
# =============================================================================
def _chain(entries: list) -> list:
    """Recalcula index, previous_hash e hash de todos os registros, em ordem.

    É o que um atacante com acesso ao arquivo faz depois de alterar registros:
    ``hash_record`` e ``genesis_hash`` são públicos (qualquer um recalcula a
    cadeia). Só a assinatura do eleitor impede forjar o conteúdo.
    """
    chained, previous = [], genesis_hash(ELECTION_ID)
    for index, entry in enumerate(entries):
        body = {k: v for k, v in entry.items() if k not in ("hash", "index", "previous_hash")}
        body.setdefault("schema_version", 1)
        body["index"] = index
        body["previous_hash"] = previous
        record = {**body, "hash": hash_record(body)}
        chained.append(record)
        previous = record["hash"]
    return chained


def read_board(public_dir: Path) -> list:
    path = public_dir / BOARD_FILE
    if not path.exists():  # nenhuma cédula publicada ainda
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def write_board(public_dir: Path, entries: list) -> None:
    """Grava registros no formato de linha do quadro real (JSON canônico + LF)."""
    text = "".join(
        json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
        for e in entries
    )
    (public_dir / BOARD_FILE).write_text(text, encoding="utf-8")


def board_voters(entries: list) -> list:
    return [entry["ballot"]["voter_id"] for entry in entries]


def board_ciphertexts(entries: list) -> list:
    """Cifras ``(c1, c2)`` de cada registro do quadro, como inteiros."""
    return [[(int(c["c1"]), int(c["c2"])) for c in entry["ballot"]["ciphertexts"]]
            for entry in entries]


def read_json(public_dir: Path, name: str):
    return json.loads((public_dir / name).read_text(encoding="utf-8"))


def write_json(public_dir: Path, name: str, data) -> None:
    (public_dir / name).write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


# =============================================================================
# Apuração
# =============================================================================
def publish_tally(public_dir: Path, authorities: Sequence[Authority], ballots: Sequence,
                  *, election_state) -> dict:
    """Agregado, parcelas de TODAS as autoridades e ``result.json``.

    ``ballots`` é uma sequência de cédulas, cada uma com um par ``(c1, c2)``
    por candidato. Usa ``publish_aggregate`` (produto homomórfico de
    ``src.crypto.homomorphic``), ``compute_authority_partials`` e
    ``combine_and_decrypt_result`` com ``inverse_mod``/``bounded_discrete_log``
    reais. ``result.json`` só é gravado se a decifração conjunta der certo.

    Cada autoridade confere o agregado contra o quadro de ``public_dir``
    (``board_path``) antes de decifrar: ``ballots`` precisa ser exatamente o
    conteúdo desse quadro, senão a autoridade recusa
    (``AggregateVerificationError``).
    """
    aggregate_data = publish_aggregate(
        ELECTION_ID, CANDIDATES, ballots, GROUP, election_state=election_state,
        aggregate_path=public_dir / "aggregate_ciphertexts.json",
    )
    election_data = load_public_json(public_dir / "election.json")
    collector = PartialDecryptionCollector(
        election_data, aggregate_data, election_state=election_state
    )
    for authority in authorities:  # cada autoridade, no seu processo
        collector.submit(compute_authority_partials(
            authority, election_data, aggregate_data,
            board_path=public_dir / BOARD_FILE,
            election_state=election_state,
        ))
    collector.save(public_dir / "authority_partials.json")
    return combine_and_decrypt_result(
        election_data, aggregate_data, collector,
        election_state=election_state,
        result_path=public_dir / "result.json",
    )


# =============================================================================
# Cenário completo
# =============================================================================
@dataclasses.dataclass
class Scenario:
    root: Path
    public_dir: Path
    private_dir: Path
    voter_keys: dict
    intruder_key: object
    joint_key: int
    election_state: str
    result: dict | None
    # Objetos vivos, para testes que continuam a eleição (ex.: enviar mais
    # cédulas). Em fixtures compartilhados (escopo de sessão), NÃO os altere.
    election: Election | None = None
    service: VotingService | None = None
    board: BulletinBoard | None = None
    authorities: tuple = ()
    receipts: dict = dataclasses.field(default_factory=dict)
    envelopes: dict = dataclasses.field(default_factory=dict)


def build_election(
    root: Path,
    rsa_keys: list,
    *,
    votes: Mapping[str, Sequence[int]] | None = None,
    until: str = "APURACAO",
    tally: bool = True,
) -> Scenario:
    """Monta a eleição em ``root`` e para depois da etapa ``until``.

    - ``votes``: ``voter_id -> vetor de m`` (um por candidato), na ordem de
      envio. Padrão: ``VOTES`` (Alice 2 x 1 Bob). Use ``{}`` para nenhum voto.
      Valores fora de {0, 1} simulam um eleitor que contorna o cliente.
    - ``until``: uma de ``STOP_STATES``. Em ``"APURACAO"``, ``tally=True``
      também publica agregado, parcelas e resultado; ``tally=False`` só faz a
      transição ``ENCERRADA -> APURACAO``.
    """
    if until not in STOP_STATES:
        raise ValueError(f"until deve ser um de {STOP_STATES}")
    if votes is None:
        votes = {voter_id: _choice_vector(candidate) for voter_id, candidate in VOTES.items()}

    public_dir = root / "data" / "public"
    private_dir = root / "data" / "private"
    public_dir.mkdir(parents=True)
    election_path = public_dir / "election.json"

    # CONFIGURACAO: candidatos publicados antes; publish_joint_public_key preserva o campo.
    election_path.write_text(json.dumps({"candidates": CANDIDATES}), encoding="utf-8")
    election = Election(
        ELECTION_ID, GROUP, CANDIDATES,
        ballots_path=public_dir / "accepted_ballots.json",
    )

    # CADASTRO: 3 eleitores (RSA) e 3 autoridades (cada uma com sua x_i em data/private/).
    registration = Registration(ELECTION_ID, p=P, q=Q, state_provider=election.current_state)
    voter_keys = {}
    for voter_id, key in zip(VOTES, rsa_keys):
        registration.register_voter(voter_id, _public_pem(key))
        voter_keys[voter_id] = key
    authorities = tuple(
        Authority.generate(str(i), GROUP, private_dir) for i in range(1, N_AUTHORITIES + 1)
    )
    for authority in authorities:
        public = authority.public_key()
        registration.register_authority(public.authority_id, public.h)
    registration.freeze()
    public_data = registration.export_public_data()
    published = publish_joint_public_key(public_data, GROUP, election_path)
    write_json(public_dir, "voters.json",
               {"election_id": ELECTION_ID, "voters": public_data["voters"]})

    # Quadro público real, criado com o cadastro congelado.
    board = BulletinBoard.create(
        public_dir / BOARD_FILE, election_id=ELECTION_ID, candidate_ids=CANDIDATES,
        voter_public_keys={v["voter_id"]: v["public_key_pem"] for v in public_data["voters"]},
    )
    service = VotingService(election, board_publisher=board_publisher_for(board))

    def snapshot(result=None, receipts=None, envelopes=None) -> Scenario:
        return Scenario(
            root=root, public_dir=public_dir, private_dir=private_dir,
            voter_keys=voter_keys, intruder_key=rsa_keys[-1],
            joint_key=int(published["joint_public_key"]),
            election_state=election.current_state(), result=result,
            election=election, service=service, board=board,
            authorities=authorities, receipts=dict(receipts or {}),
            envelopes=dict(envelopes or {}),
        )

    if until == "CADASTRO":
        return snapshot()

    # VOTACAO_ABERTA -> ENCERRADA
    service.open_voting(public_data, election_path=election_path)
    h = election.joint_public_key
    envelopes, receipts = {}, {}
    for voter_id, vector in votes.items():
        envelopes[voter_id] = encrypted_ballot(voter_id, voter_keys[voter_id], vector, h)
        receipts[voter_id] = service.receive_ballot(envelopes[voter_id])
    if until == "VOTACAO_ABERTA":
        return snapshot(receipts=receipts, envelopes=envelopes)
    service.close_voting()
    if until == "ENCERRADA":
        return snapshot(receipts=receipts, envelopes=envelopes)

    # APURACAO: produto homomórfico, parcelas e resultado.
    election.start_tally()
    result = None
    if tally:
        result = publish_tally(
            public_dir, authorities, [record.ciphertexts for record in election.accepted_ballots],
            election_state=election.current_state,
        )
    return snapshot(result=result, receipts=receipts, envelopes=envelopes)


# =============================================================================
# Auditoria e adulterações do quadro
# =============================================================================
def audit(public_dir: Path, **kwargs) -> AuditReport:
    return Auditor(public_dir, **kwargs).run()


def failed(report: AuditReport) -> set:
    return {check.name for check in report.failures}


def errors_of(report: AuditReport, name: str) -> str:
    return "\n".join(report.check(name).errors)


def _forged_entry(voter_id: str, private, candidate: str, h: int) -> dict:
    """Corpo de registro com assinatura válida de ``private`` (sem index/hash).

    Passe por ``_chain`` para obter um registro com a cadeia recalculada.
    """
    envelope = _ballot(voter_id, private, candidate, h)
    return {"schema_version": 1, "ballot": envelope["ballot"], "signature": envelope["signature"]}
