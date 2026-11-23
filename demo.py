#!/usr/bin/env python3
"""Roteiro automatizado da demonstração do URNA_ONLINE (Issue T15 / #18).

Uso::

    python demo.py                        # execução contínua, saída em data/demo/
    python demo.py --pause                # espera Enter entre as etapas (apresentação)
    python demo.py --output-dir /tmp/x    # outro diretório de saída

Requisito de plataforma: o quadro público real (``src.bulletin_board.board``)
usa ``fcntl``, disponível em Linux, macOS e WSL. No Windows nativo o demo
para ANTES de criar qualquer arquivo, com uma mensagem clara (código 3).

Cada execução apaga e recria o diretório de saída (só se ele tiver sido criado
pelo demo, marcado com ``.urna_demo``) com::

    <saída>/public/            dados públicos da eleição (o que o auditor lê)
    <saída>/private/           chaves x_i das autoridades (nunca publicadas)
    <saída>/tampered_public/   cópia de public/ com uma cédula adulterada

Usa SÓ os módulos reais do projeto, sem mocks nem valores fixos no lugar de
cifras: ``src.crypto`` (grupo RFC 3526, ElGamal exponencial, envelope assinado
RSA-PSS, recibos), ``Registration``, ``Election``/``VotingService``,
``BulletinBoard`` (ligado por ``board_publisher_for``), ``Authority``,
``partial_decryption`` (``publish_aggregate``, parcelas com prova de
Chaum-Pedersen, decifração conjunta) e o ``Auditor`` independente.

Reprodutível = mesmo cenário, mesmas decisões e mesmos totais. A aleatoriedade
criptográfica (r, x_i, chaves RSA) continua vindo de ``secrets``/``os.urandom``.

A lógica fica em ``run_demo``, que devolve um ``DemoReport`` estruturado;
``main`` só formata a saída e define o código de saída:
0 = tudo conferiu, 1 = alguma etapa divergiu, 2 = diretório de saída recusado,
3 = plataforma sem ``fcntl``, 130 = interrompido pelo usuário (Ctrl+C, ou
Ctrl+D/fim da entrada no prompt do ``--pause``), sem traceback.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import sys
import textwrap
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Nenhum destes módulos importa fcntl. O quadro público e os recibos do
# servidor (que importam src.bulletin_board.board) são carregados só depois da
# checagem de plataforma, em _load_board_modules().
from src.auditor.auditor import CHECK_HASH_CHAIN, CHECK_SIGNATURES, AuditReport, Auditor  # noqa: E402
from src.authorities.authority import Authority, publish_joint_public_key  # noqa: E402
from src.authorities.partial_decryption import (  # noqa: E402
    AggregateVerificationError,
    MissingAuthorityShareError,
    PartialDecryptionCollector,
    build_aggregate,
    combine_and_decrypt_result,
    compute_authority_partials,
    load_public_json,
    publish_aggregate,
)
from src.crypto.ballots import sign_ballot  # noqa: E402
from src.crypto.elgamal import encrypt_bit  # noqa: E402
from src.crypto.group import DEFAULT_PARAMETERS, is_group_element, validate_parameters  # noqa: E402
from src.crypto.keys import public_key_to_pem  # noqa: E402
from src.crypto.receipts import verify_receipt_in_board  # noqa: E402
from src.crypto.signatures import generate_signing_key  # noqa: E402
from src.election.election import (  # noqa: E402
    DuplicateVoteError,
    Election,
    VotingClosedError,
    compute_receipt,
)
from src.election.states import ElectionState  # noqa: E402
from src.server.registration import Registration  # noqa: E402
from src.server.voting import VotingService, board_publisher_for  # noqa: E402

# =============================================================================
# Cenário fixo (o mesmo a cada execução)
# =============================================================================
ELECTION_ID = "demo-t15"
CANDIDATES = ("Alice", "Bob")  # identificadores: vão dentro da cédula assinada
# Ordem de envio e voto de cada eleitor (A, B, A): define o resultado esperado.
VOTE_PLAN = (
    ("eleitor-1", "Alice"),
    ("eleitor-2", "Bob"),
    ("eleitor-3", "Alice"),
)
EXPECTED_TOTALS = {c: sum(1 for _, choice in VOTE_PLAN if choice == c) for c in CANDIDATES}
N_AUTHORITIES = 3
AUTHORITY_IDS = tuple(str(i) for i in range(1, N_AUTHORITIES + 1))

DUPLICATE_VOTER, DUPLICATE_CHOICE = "eleitor-2", "Alice"  # etapa 4
LATE_VOTER, LATE_CHOICE = "eleitor-3", "Bob"               # etapa 5
ABSENT_AUTHORITY = "3"                                     # etapa 6
TARGET_VOTER, ATTACKED_AUTHORITY = "eleitor-1", "1"        # etapa 7: agregado forjado
TAMPER_ENTRY, TAMPER_CANDIDATE = 1, "Alice"                # etapa 8: c2 · g (+1 voto)

# Parâmetros: os MESMOS do projeto, sem redução para a demo.
GROUP = DEFAULT_PARAMETERS          # RFC 3526 MODP-14: p de 2048 bits
RSA_KEY_SIZE = 3072                 # padrão de src.crypto.signatures.generate_signing_key

DEFAULT_OUTPUT_DIR = ROOT / "data" / "demo"
MARKER_FILE = ".urna_demo"
BOARD_FILE = "bulletin_board.jsonl"
AGGREGATE_FILE = "aggregate_ciphertexts.json"
PARTIALS_FILE = "authority_partials.json"
RESULT_FILE = "result.json"
SERVER_KEY_FILE = "server_public_key.pem"
TIME_TARGET_S = 30.0
TOTAL_STEPS = 9

EXIT_OK, EXIT_DIVERGED, EXIT_BAD_OUTPUT_DIR, EXIT_NO_FCNTL = 0, 1, 2, 3
# Convenção do shell para término por SIGINT (128 + 2); distinto de 0 a 3.
EXIT_INTERRUPTED = 130
INTERRUPTED_MESSAGE = "Demonstração interrompida pelo usuário"


class DemoPlatformError(RuntimeError):
    """A plataforma não tem o que o quadro público real exige (``fcntl``)."""


NO_FCNTL_MESSAGE = (
    "o quadro público (src/bulletin_board/board.py) usa fcntl para travar o arquivo, "
    "que só existe em Linux, macOS e WSL. Rode a demonstração no WSL "
    "(ex.: wsl -- python3 demo.py) ou em Linux/macOS. Nenhum arquivo foi criado."
)


def fcntl_available() -> bool:
    return importlib.util.find_spec("fcntl") is not None


def _load_board_modules() -> SimpleNamespace:
    """Importa o quadro real e os recibos do servidor (ambos usam fcntl)."""
    if not fcntl_available():
        raise DemoPlatformError(NO_FCNTL_MESSAGE)
    try:
        from src.bulletin_board.board import BulletinBoard
        from src.server.receipts import issue_receipt
    except ModuleNotFoundError as exc:  # defesa extra: fcntl some no meio do caminho
        if exc.name == "fcntl":
            raise DemoPlatformError(NO_FCNTL_MESSAGE) from None
        raise
    return SimpleNamespace(BulletinBoard=BulletinBoard, issue_receipt=issue_receipt)


# =============================================================================
# Relatório estruturado
# =============================================================================
@dataclass
class StepReport:
    """Resultado de uma etapa: o que se esperava, o que se obteve e cada conferência."""

    number: int
    title: str
    concept: str
    expected: str
    obtained: str = ""
    ok: bool = False
    checks: list[tuple[str, bool]] = field(default_factory=list)
    details: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    elapsed: float = 0.0

    def check(self, description: str, condition: bool) -> bool:
        self.checks.append((description, bool(condition)))
        return bool(condition)

    @property
    def failed_checks(self) -> list[str]:
        return [desc for desc, ok in self.checks if not ok]


@dataclass
class DemoReport:
    output_dir: Path
    public_dir: Path
    private_dir: Path
    tampered_dir: Path
    steps: list[StepReport] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    expected_totals: dict[str, int] = field(default_factory=lambda: dict(EXPECTED_TOTALS))
    totals: dict[str, int] | None = None
    elapsed: float = 0.0          # sem as pausas
    paused: float = 0.0           # tempo esperando Enter

    @property
    def success(self) -> bool:
        return len(self.steps) == TOTAL_STEPS and all(step.ok for step in self.steps)

    def step(self, number: int) -> StepReport:
        for step in self.steps:
            if step.number == number:
                return step
        raise KeyError(number)


# =============================================================================
# Utilidades
# =============================================================================
def short(value: int | str, n: int = 16) -> str:
    """Primeiros ``n`` dígitos hex de um inteiro grande ou de um hash, com o tamanho."""
    if isinstance(value, int):
        text = format(value, "x")
        if len(text) <= n:
            return f"0x{text}"
        return f"0x{text[:n]}… ({value.bit_length()} bits)"
    return value if len(value) <= n else f"{value[:n]}…"


def directory_digest(path: Path) -> str:
    """SHA-256 dos nomes e conteúdos de todos os arquivos (para provar que nada mudou)."""
    digest = hashlib.sha256()
    for file in sorted(p for p in path.rglob("*") if p.is_file()):
        digest.update(file.relative_to(path).as_posix().encode() + b"\0")
        digest.update(file.read_bytes() + b"\0")
    return digest.hexdigest()


def _is_within(child: Path, parent: Path) -> bool:
    return child == parent or parent in child.parents


def prepare_output_dir(output_dir: Path | str) -> Path:
    """Apaga e recria o diretório de saída do demo, com travas de segurança.

    Recusa ``data/public``, ``data/private``, a raiz do projeto e qualquer
    diretório que os contenha ou esteja dentro deles. Um diretório existente
    só é apagado se for vazio ou tiver o marcador ``.urna_demo`` (criado por
    uma execução anterior), para nunca apagar dados de outra pessoa.
    """
    target = Path(output_dir).expanduser().resolve()
    protected = {
        (ROOT / "data" / "public").resolve(),
        (ROOT / "data" / "private").resolve(),
        Path("data/public").resolve(),
        Path("data/private").resolve(),
    }
    for path in protected:
        if _is_within(target, path) or _is_within(path, target):
            raise ValueError(
                f"diretório de saída {target} sobrepõe {path}: o demo nunca escreve "
                "em data/public/ nem em data/private/ reais"
            )
    if _is_within(ROOT, target):
        raise ValueError(f"diretório de saída {target} contém o projeto inteiro")
    if target.exists():
        if not target.is_dir():
            raise ValueError(f"{target} existe e não é um diretório")
        if any(target.iterdir()) and not (target / MARKER_FILE).is_file():
            raise ValueError(
                f"{target} não está vazio e não foi criado pelo demo (falta {MARKER_FILE}); "
                "escolha outro --output-dir"
            )
        shutil.rmtree(target)
    target.mkdir(parents=True)
    (target / MARKER_FILE).write_text(
        "Diretório gerado por demo.py; apagado e recriado a cada execução.\n", encoding="utf-8"
    )
    (target / "public").mkdir()
    (target / "private").mkdir()
    return target


def audit_public_dir(public_dir: Path) -> AuditReport:
    """Auditor independente sobre ``public_dir``.

    O ``Auditor`` importa só ``src.crypto`` e ``src.bulletin_board`` e abre
    apenas os arquivos públicos desse diretório: não recebe nenhum objeto do
    servidor nem enxerga ``private/``.
    """
    return Auditor(public_dir).run()


def _attempt(action: Callable[[], Any]) -> BaseException | None:
    """Executa ``action`` e devolve a exceção (``None`` se não houve)."""
    try:
        action()
    except Exception as exc:  # o chamador confere o tipo esperado
        return exc
    return None


def _describe(exc: BaseException | None) -> str:
    return "nenhum erro (aceito)" if exc is None else f"{type(exc).__name__}: {exc}"


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_board(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


# =============================================================================
# Cliente do eleitor (não existe em src/): só API pública de src.crypto
# =============================================================================
@dataclass
class VoterClient:
    voter_id: str
    private_key: Any = field(repr=False)

    @classmethod
    def generate(cls, voter_id: str) -> "VoterClient":
        return cls(voter_id, generate_signing_key(RSA_KEY_SIZE))

    @property
    def public_key_pem(self) -> str:
        return public_key_to_pem(self.private_key.public_key())

    def build_ballot(self, choice: str, joint_public_key: int) -> dict:
        """Um bit por candidato com ``encrypt_bit``; envelope assinado com ``sign_ballot``.

        O ``r`` de cada cifra é descartado aqui: ele não entra na cédula nem no
        recibo (revelá-lo provaria o voto).
        """
        ciphertexts = []
        for candidate in CANDIDATES:
            ciphertext, _r = encrypt_bit(1 if candidate == choice else 0, joint_public_key, GROUP)
            ciphertexts.append(
                {"candidate_id": candidate, "c1": str(ciphertext.a), "c2": str(ciphertext.b)}
            )
        ballot = {
            "schema_version": 1,
            "election_id": ELECTION_ID,
            "voter_id": self.voter_id,
            "ciphertexts": ciphertexts,
        }
        return sign_ballot(ballot, self.private_key)


# =============================================================================
# Etapas
# =============================================================================
def _step1_configuration(s: SimpleNamespace, step: StepReport) -> None:
    validate_parameters(GROUP, check_primality=True)
    _write_json(s.public / "election.json", {"candidates": list(CANDIDATES)})
    s.election = Election(
        ELECTION_ID, GROUP, CANDIDATES,
        ballots_path=s.public / "accepted_ballots.json",
    )
    step.details += [
        f"grupo {GROUP.name}: p = {short(GROUP.p)}",
        f"q = (p-1)/2 = {short(GROUP.q)}   g = {GROUP.g}",
        "Miller-Rabin (32 rodadas) em p e q; g^q ≡ 1 (mod p)",
        f"candidatos: {', '.join(CANDIDATES)}   eleição: {ELECTION_ID!r}",
    ]
    step.data.update(p_bits=GROUP.p.bit_length(), q_bits=GROUP.q.bit_length(), g=GROUP.g,
                     state=s.election.current_state(), candidates=list(CANDIDATES))
    step.check("p tem pelo menos 2048 bits", GROUP.p.bit_length() >= 2048)
    step.check("eleição em CADASTRO", s.election.state is ElectionState.CADASTRO)
    step.check("dois candidatos", s.election.candidates == CANDIDATES)
    step.obtained = (f"grupo validado (p {GROUP.p.bit_length()} bits); etapa "
                     f"{s.election.current_state()}; candidatos {', '.join(CANDIDATES)}")


def _step2_registration(s: SimpleNamespace, step: StepReport) -> None:
    registration = Registration(ELECTION_ID, p=GROUP.p, q=GROUP.q,
                                state_provider=s.election.current_state)
    # Cada autoridade gera x_i no "seu processo" e só entrega h_i. O objeto
    # Authority é descartado: as etapas 6 e 7 recarregam a chave de private/.
    authority_keys = []
    for authority_id in AUTHORITY_IDS:
        public = Authority.generate(authority_id, GROUP, s.private).public_key()
        registration.register_authority(public.authority_id, public.h)
        authority_keys.append(public)
    s.clients = {voter_id: VoterClient.generate(voter_id) for voter_id, _ in VOTE_PLAN}
    for client in s.clients.values():
        registration.register_voter(client.voter_id, client.public_key_pem)
    registration.freeze()
    s.public_data = registration.export_public_data()
    published = publish_joint_public_key(s.public_data, GROUP, s.public / "election.json")
    _write_json(s.public / "voters.json",
                {"election_id": ELECTION_ID, "voters": s.public_data["voters"]})

    # Quadro público real e chave do servidor (assina os recibos). A chave
    # privada do servidor fica só em memória; a pública é publicada.
    s.voter_keys = {v["voter_id"]: v["public_key_pem"] for v in s.public_data["voters"]}
    s.board = s.mods.BulletinBoard.create(
        s.public / BOARD_FILE, election_id=ELECTION_ID, candidate_ids=CANDIDATES,
        voter_public_keys=s.voter_keys,
    )
    s.server_key = generate_signing_key(RSA_KEY_SIZE)
    s.server_public_pem = public_key_to_pem(s.server_key.public_key())
    (s.public / SERVER_KEY_FILE).write_text(s.server_public_pem, encoding="ascii")
    s.service = VotingService(s.election, board_publisher=board_publisher_for(s.board))

    product = 1
    for key in authority_keys:
        product = product * key.h % GROUP.p
    s.joint_key = int(published["joint_public_key"])

    for key in authority_keys:
        step.details.append(f"autoridade {key.authority_id}: h_{key.authority_id} = {short(key.h)}")
    step.details.append(f"chave conjunta h = h_1·h_2·h_3 mod p = {short(s.joint_key)}")
    for client in s.clients.values():
        step.details.append(f"{client.voter_id}: RSA {RSA_KEY_SIZE} bits (só a chave pública é cadastrada)")
    key_files = sorted(p.name for p in s.private.iterdir())
    step.details.append(f"chaves privadas em private/: {', '.join(key_files)}")

    public_text = "".join(p.read_text(encoding="utf-8") for p in s.public.iterdir() if p.is_file())
    secrets_x = [str(json.loads((s.private / f"authority_{a}.key").read_text())["x"])
                 for a in AUTHORITY_IDS]
    step.data.update(authority_h={k.authority_id: k.h for k in authority_keys},
                     joint_public_key=s.joint_key, voters=list(s.clients), key_files=key_files)
    step.check("3 autoridades com h_i distintos no subgrupo",
               len({k.h for k in authority_keys}) == N_AUTHORITIES
               and all(is_group_element(k.h, GROUP) for k in authority_keys))
    step.check("h publicado = h_1·h_2·h_3 mod p", s.joint_key == product)
    step.check("3 eleitores cadastrados", len(s.public_data["voters"]) == len(VOTE_PLAN))
    step.check("chaves x_i só em private/",
               key_files == [f"authority_{a}.key" for a in AUTHORITY_IDS]
               and not any(x in public_text for x in secrets_x))
    step.check("nenhuma chave privada RSA nos dados públicos", "PRIVATE KEY" not in public_text)
    step.check("cadastro congelado", s.public_data["frozen"] is True)
    step.obtained = f"{N_AUTHORITIES} autoridades, h conjunta conferida, {len(s.clients)} eleitores; cadastro congelado"


def _step3_votes(s: SimpleNamespace, step: StepReport) -> None:
    s.service.open_voting(s.public_data, election_path=s.public / "election.json")
    s.envelopes, s.receipts, s.signed_receipts = {}, {}, {}
    for voter_id, choice in VOTE_PLAN:
        envelope = s.clients[voter_id].build_ballot(choice, s.election.joint_public_key)
        receipt = s.service.receive_ballot(envelope)  # Election valida; quadro reverifica e grava
        signed = s.mods.issue_receipt(s.board, voter_id=voter_id, server_private_key=s.server_key)
        s.envelopes[voter_id], s.receipts[voter_id], s.signed_receipts[voter_id] = envelope, receipt, signed
        step.details.append(
            f"{voter_id} (vota {choice}) → recibo #{receipt.index} {short(receipt.receipt)}  "
            f"c1[{CANDIDATES[0]}] = {short(int(envelope['ballot']['ciphertexts'][0]['c1']))}"
        )
    records = s.board.records()  # releitura verificada pelo próprio quadro
    for record in records:
        step.details.append(
            f"quadro #{record['index']}: previous {short(record['previous_hash'])} → hash {short(record['hash'])}"
        )
    # Cada eleitor confere o PRÓPRIO recibo: assinatura do servidor, sua cédula
    # e o quadro completo, contra o checkpoint (tamanho e hash final) atual.
    checkpoint = s.board.checkpoint
    verified = {}
    for voter_id, signed in s.signed_receipts.items():
        found = verify_receipt_in_board(
            signed, records, submitted_envelope=s.envelopes[voter_id],
            election_id=ELECTION_ID, voter_id=voter_id, server_public_key_pem=s.server_public_pem,
            candidate_ids=CANDIDATES, voter_public_keys=s.voter_keys, expected_checkpoint=checkpoint,
        )
        verified[voter_id] = found["hash"] == signed["receipt"]["record_hash"]
    step.details.append(
        f"recibos assinados pelo servidor (RSA-PSS) conferidos no quadro: "
        f"{sum(verified.values())}/{len(verified)}; checkpoint {checkpoint['size']} registros, "
        f"hash final {short(checkpoint['head_hash'])}"
    )
    step.data.update(receipts={v: r.receipt for v, r in s.receipts.items()},
                     record_hashes={v: r["receipt"]["record_hash"] for v, r in s.signed_receipts.items()},
                     board_size=len(records), state=s.election.current_state())
    step.check("votação aberta (VOTACAO_ABERTA)", s.election.state is ElectionState.VOTACAO_ABERTA)
    step.check("3 recibos com índices 0, 1, 2",
               [r.index for r in s.receipts.values()] == list(range(len(VOTE_PLAN))))
    step.check("3 registros no quadro público", len(records) == len(VOTE_PLAN))
    step.check("recibo da eleição recalculável a partir do registro do quadro",
               [compute_receipt(r["ballot"], r["signature"]) for r in records]
               == [s.receipts[v].receipt for v, _ in VOTE_PLAN])
    step.check("cada recibo assinado aponta o registro do eleitor e confere no quadro",
               all(verified.values()) and len(verified) == len(VOTE_PLAN))
    step.check("aleatoriedade nova em cada cifra (c1 distintos)",
               len({c["c1"] for r in records for c in r["ballot"]["ciphertexts"]})
               == len(records) * len(CANDIDATES))
    step.obtained = (f"{len(records)} cédulas aceitas e no quadro; {len(verified)} recibos "
                     "assinados e conferidos pelos eleitores")


def _step4_duplicate(s: SimpleNamespace, step: StepReport) -> None:
    board_before = (s.public / BOARD_FILE).read_bytes()
    envelope = s.clients[DUPLICATE_VOTER].build_ballot(DUPLICATE_CHOICE, s.election.joint_public_key)
    error = _attempt(lambda: s.service.receive_ballot(envelope))
    step.details.append(f"{DUPLICATE_VOTER} envia nova cédula (voto {DUPLICATE_CHOICE}), assinada corretamente")
    step.details.append(f"motivo: {_describe(error)}")
    step.data.update(error_type=type(error).__name__ if error else None, error=str(error) if error else None)
    step.check("rejeitada com DuplicateVoteError", isinstance(error, DuplicateVoteError))
    step.check("quadro público inalterado", (s.public / BOARD_FILE).read_bytes() == board_before)
    step.check("continuam 3 cédulas aceitas", len(s.election.accepted_ballots) == len(VOTE_PLAN))
    step.check("cédula original preservada",
               s.election.accepted_ballots[s.receipts[DUPLICATE_VOTER].index].receipt
               == s.receipts[DUPLICATE_VOTER].receipt)
    step.obtained = f"rejeitada — {_describe(error)}"


def _step5_close(s: SimpleNamespace, step: StepReport) -> None:
    s.service.close_voting()
    board_before = (s.public / BOARD_FILE).read_bytes()
    envelope = s.clients[LATE_VOTER].build_ballot(LATE_CHOICE, s.election.joint_public_key)
    error = _attempt(lambda: s.service.receive_ballot(envelope))
    step.details.append(f"etapa: VOTACAO_ABERTA → {s.election.current_state()}")
    step.details.append(f"{LATE_VOTER} tenta votar depois do encerramento (a etapa é conferida antes de tudo)")
    step.details.append(f"motivo: {_describe(error)}")
    step.data.update(state=s.election.current_state(),
                     late_error_type=type(error).__name__ if error else None)
    step.check("eleição ENCERRADA", s.election.state is ElectionState.ENCERRADA)
    step.check("voto tardio rejeitado com VotingClosedError", isinstance(error, VotingClosedError))
    step.check("quadro público inalterado", (s.public / BOARD_FILE).read_bytes() == board_before)
    step.check("nenhum resultado publicado antes da apuração", not (s.public / RESULT_FILE).exists())
    step.obtained = f"etapa {s.election.current_state()}; voto tardio rejeitado — {type(error).__name__ if error else 'aceito'}"


def _authority_partials(s: SimpleNamespace, authority_id: str, aggregate: dict | None = None):
    """O que roda no processo da autoridade: carrega SUA x_i e calcula d_i e a prova.

    Antes de decifrar, a autoridade lê o quadro público por conta própria
    (``board_path``) e confere o agregado recebido do servidor
    (``AggregateVerificationError`` se não conferir).
    """
    authority = Authority.load(authority_id, GROUP, s.private)
    return compute_authority_partials(
        authority, s.election_data, s.aggregate if aggregate is None else aggregate,
        board_path=s.public / BOARD_FILE,
        election_state=s.election.current_state,
    )


def _step6_missing_authority(s: SimpleNamespace, step: StepReport) -> None:
    s.election.start_tally()
    s.aggregate = publish_aggregate(
        ELECTION_ID, CANDIDATES, [b.ciphertexts for b in s.election.accepted_ballots], GROUP,
        election_state=s.election.current_state, aggregate_path=s.public / AGGREGATE_FILE,
    )
    s.election_data = load_public_json(s.public / "election.json")
    present = [a for a in AUTHORITY_IDS if a != ABSENT_AUTHORITY]
    submissions = [_authority_partials(s, a) for a in present]
    error = _attempt(lambda: combine_and_decrypt_result(
        s.election_data, s.aggregate, submissions,
        election_state=s.election.current_state, result_path=s.public / RESULT_FILE,
    ))
    for cid, pair in s.aggregate["ciphertexts"].items():
        step.details.append(f"produto {cid}: C1 = {short(int(pair['c1']))}  C2 = {short(int(pair['c2']))}")
    step.details.append(f"parcelas recebidas: autoridades {', '.join(present)}; ausente: {ABSENT_AUTHORITY}")
    step.details.append(f"motivo: {_describe(error)}")
    step.data.update(present=present, absent=ABSENT_AUTHORITY,
                     error_type=type(error).__name__ if error else None, error=str(error) if error else None)
    step.check("etapa APURACAO", s.election.state is ElectionState.APURACAO)
    step.check("agregado publicado com as 3 cédulas", s.aggregate.get("ballot_count") == len(VOTE_PLAN))
    step.check("falha com MissingAuthorityShareError", isinstance(error, MissingAuthorityShareError))
    step.check(f"erro aponta a autoridade ausente {ABSENT_AUTHORITY!r}",
               error is not None and repr(ABSENT_AUTHORITY) in str(error))
    step.check("nenhum result.json publicado", not (s.public / RESULT_FILE).exists())
    step.obtained = f"apuração interrompida — {_describe(error)}"


def _step7_full_tally(s: SimpleNamespace, step: StepReport) -> None:
    # Ataque ao sigilo: o servidor envia a uma autoridade a cifra de UMA cédula
    # como se fosse o agregado. Se ela decifrasse, o voto daquele eleitor vazaria.
    target = next(b for b in s.election.accepted_ballots if b.voter_id == TARGET_VOTER)
    forged = build_aggregate(ELECTION_ID, CANDIDATES, [target.ciphertexts], GROUP)
    attack_error = _attempt(lambda: _authority_partials(s, ATTACKED_AUTHORITY, forged))
    step.details.append(
        f"servidor malicioso envia à autoridade {ATTACKED_AUTHORITY} só a cédula de "
        f"{TARGET_VOTER} como agregado (ballot_count {forged['ballot_count']})"
    )
    step.details.append(f"recusa: {_describe(attack_error)}")
    step.data.update(attack_error_type=type(attack_error).__name__ if attack_error else None,
                     attack_error=str(attack_error) if attack_error else None)
    step.check("autoridade recusa o agregado forjado com AggregateVerificationError",
               isinstance(attack_error, AggregateVerificationError))

    collector = PartialDecryptionCollector(
        s.election_data, s.aggregate, election_state=s.election.current_state
    )
    for authority_id in AUTHORITY_IDS:
        submission = _authority_partials(s, authority_id)
        collector.submit(submission)  # verifica a prova de Chaum-Pedersen
        shares = "  ".join(f"d({c}) = {short(submission.share_for(c).d, 12)}" for c in CANDIDATES)
        step.details.append(f"autoridade {authority_id}: {shares}  prova ✔")
    collector.save(s.public / PARTIALS_FILE)
    result = combine_and_decrypt_result(
        s.election_data, s.aggregate, collector,
        election_state=s.election.current_state, result_path=s.public / RESULT_FILE,
    )
    totals = dict(result["totals"])
    s.totals = totals
    for cid in CANDIDATES:
        step.details.append(f"{cid}: {totals.get(cid)} voto(s) (esperado {EXPECTED_TOTALS[cid]})")
    step.details.append(
        f"limite de cada total: [0, {result.get('max_votes')}] (cédulas aceitas); "
        f"soma dos totais: {sum(totals.values())} = {s.aggregate.get('ballot_count')} cédulas"
    )
    step.data.update(totals=totals, max_votes=result.get("max_votes"))
    step.check("todas as autoridades participaram", collector.is_complete)
    step.check("result.json publicado", (s.public / RESULT_FILE).exists())
    step.check("totais iguais à distribuição definida", totals == EXPECTED_TOTALS)
    step.check("limite dos totais = número de cédulas", result.get("max_votes") == len(VOTE_PLAN))
    step.check("soma dos totais = número de cédulas", sum(totals.values()) == len(VOTE_PLAN))
    step.obtained = "totais publicados: " + ", ".join(f"{c} {totals[c]}" for c in CANDIDATES)


def _step8_audit_valid(s: SimpleNamespace, step: StepReport) -> None:
    report = audit_public_dir(s.public)
    s.valid_report = report
    for check in report.checks:
        step.details.append(f"{'✔' if check.passed else '✘'} {check.description}")
        step.details.extend(f"    - {error}" for error in check.errors)
    if report.valid:
        s.election.mark_audited()

    # Cópia e adulteração: só na cópia; public/ não pode mudar.
    s.public_digest = directory_digest(s.public)
    shutil.copytree(s.public, s.tampered)
    entries = _read_board(s.tampered / BOARD_FILE)
    position = CANDIDATES.index(TAMPER_CANDIDATE)
    target = entries[TAMPER_ENTRY]["ballot"]["ciphertexts"][position]
    original_c2 = int(target["c2"])
    target["c2"] = str(original_c2 * GROUP.g % GROUP.p)  # m → m+1, sem refazer hash nem assinatura
    (s.tampered / BOARD_FILE).write_text(
        "".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n" for e in entries),
        encoding="utf-8",
    )
    voter = entries[TAMPER_ENTRY]["ballot"]["voter_id"]
    step.details.append(
        f"cópia {s.tampered.name}/: entrada {TAMPER_ENTRY} ({voter}), c2[{TAMPER_CANDIDATE}] "
        f"{short(original_c2, 12)} → {short(int(target['c2']), 12)} (× g = +1 voto)"
    )
    step.data.update(valid=report.valid, failed_checks=[c.name for c in report.failures],
                     state=s.election.current_state(), tampered_voter=voter)
    step.check("auditor aprova os dados públicos válidos", report.valid)
    step.check("eleição marcada como AUDITADA", s.election.state is ElectionState.AUDITADA)
    step.check("cópia adulterada difere do original",
               (s.tampered / BOARD_FILE).read_bytes() != (s.public / BOARD_FILE).read_bytes())
    step.check("public/ intacto após a adulteração da cópia", directory_digest(s.public) == s.public_digest)
    step.obtained = (f"auditor: ELEIÇÃO VÁLIDA ({len(report.checks)}/{len(report.checks)} verificações); "
                     "cópia adulterada criada" if report.valid
                     else f"auditor reprovou dados válidos: {list(report.errors)}")


def _step9_audit_tampered(s: SimpleNamespace, step: StepReport) -> None:
    report = audit_public_dir(s.tampered)
    where = f"entrada {TAMPER_ENTRY}"
    for check in report.checks:
        step.details.append(f"{'✔' if check.passed else '✘'} {check.description}")
        step.details.extend(f"    - {error}" for error in check.errors)
    failed = {c.name: list(c.errors) for c in report.failures}
    step.data.update(valid=report.valid, failed_checks=failed)
    step.check("auditor reprova a cópia adulterada", not report.valid)
    step.check(f"cadeia de hashes acusa a {where}",
               any(e.startswith(where) for e in failed.get(CHECK_HASH_CHAIN, [])))
    step.check(f"assinatura do eleitor acusa a {where}",
               any(e.startswith(where) for e in failed.get(CHECK_SIGNATURES, [])))
    step.check("public/ continua intacto", directory_digest(s.public) == s.public_digest)
    names = ", ".join(failed) or "nenhuma"
    step.obtained = f"ELEIÇÃO INVÁLIDA — falharam: {names} (adulteração na {where})"


STEPS = (
    (1, "Configuração da eleição",
     "Grupo RFC 3526 (MODP 14): p primo seguro de 2048 bits, q = (p-1)/2 primo e g = 2 "
     "de ordem q. O ElGamal exponencial opera nesse subgrupo.",
     "parâmetros válidos e eleição em CADASTRO com 2 candidatos",
     _step1_configuration),
    (2, "Autoridades e eleitores",
     "Cada autoridade sorteia x_i e publica só h_i = g^x_i mod p. A chave conjunta é "
     "h = Πh_i = g^Σx_i, e ninguém conhece Σx_i. Eleitores cadastram chaves públicas RSA.",
     "3 autoridades, h = h_1·h_2·h_3 mod p, 3 eleitores e nenhuma chave privada pública",
     _step2_registration),
    (3, "Votos válidos e recibos",
     "Cada eleitor cifra um bit por candidato, (c1, c2) = (g^r, g^m·h^r mod p), e assina "
     "com RSA-PSS. O quadro encadeia hashes; o servidor assina um recibo que não revela o voto.",
     f"{len(VOTE_PLAN)} cédulas aceitas, cada recibo conferido pelo eleitor no quadro",
     _step3_votes),
    (4, "Tentativa de voto duplicado",
     "O servidor lembra quem já votou: uma 2ª cédula, mesmo com assinatura válida, é "
     "rejeitada antes de qualquer efeito; o voto original é preservado.",
     "rejeição com DuplicateVoteError e quadro inalterado",
     _step4_duplicate),
    (5, "Encerramento da votação",
     "A máquina de estados só avança (VOTACAO_ABERTA → ENCERRADA): depois disso nenhuma "
     "cédula entra e ainda não há resultado.",
     "etapa ENCERRADA e voto tardio rejeitado com VotingClosedError",
     _step5_close),
    (6, "Apuração sem uma das autoridades",
     "Π(g^m·h^r) = g^T·h^R soma os votos sem decifrá-los. Remover h^R exige d_i = C1^x_i de "
     "TODAS as autoridades; sem uma, g^T não aparece.",
     f"falha explícita (MissingAuthorityShareError) apontando a autoridade {ABSENT_AUTHORITY}",
     _step6_missing_authority),
    (7, "Apuração com todas as autoridades",
     "Antes de decifrar, cada autoridade lê o quadro, confere cadeia e assinaturas e "
     "recalcula o produto e o nº de cédulas: um agregado forjado é recusado. Cada d_i vem "
     "com prova de Chaum-Pedersen (mesmo x_i de h_i). g^T = C2·(Πd_i)^-1 e T sai do "
     "logaritmo discreto limitado a [0, nº de cédulas]; a soma dos totais tem de ser o "
     "nº de cédulas.",
     "agregado forjado recusado; totais "
     + ", ".join(f"{c} {n}" for c, n in EXPECTED_TOTALS.items()),
     _step7_full_tally),
    (8, "Auditoria dos dados válidos e adulteração da cópia",
     "O auditor lê só public/: refaz cadeia de hashes, assinaturas e produto homomórfico e "
     "confere C2 ≡ g^T·Πd_i, sem chave privada. Depois, adulteramos uma cifra numa cópia.",
     "auditor aprova; adulteração feita só na cópia",
     _step8_audit_valid),
    (9, "Auditoria da cópia adulterada",
     "Mudar a cifra altera o hash do registro (quebra a cadeia) e invalida a assinatura do "
     "eleitor: o auditor reprova e aponta a entrada.",
     f"auditor reprova, apontando cadeia e assinatura na entrada {TAMPER_ENTRY}",
     _step9_audit_tampered),
)


# =============================================================================
# Execução
# =============================================================================
def run_demo(
    output_dir: Path | str = DEFAULT_OUTPUT_DIR,
    pause: bool = False,
    *,
    on_step: Callable[[StepReport], None] | None = None,
    wait: Callable[[str], Any] | None = None,
) -> DemoReport:
    """Executa as 9 etapas e devolve o relatório. Não imprime nada.

    - Lança ``DemoPlatformError`` (sem criar nada) se faltar ``fcntl`` e
      ``ValueError`` se o diretório de saída for recusado.
    - ``on_step`` é chamado ao fim de cada etapa (o ``main`` usa para imprimir).
    - ``pause=True`` chama ``wait`` (padrão: ``input``) entre as etapas; esse
      tempo não entra em ``DemoReport.elapsed``.
    - Para na primeira etapa que divergir do esperado: as seguintes dependem dela.
    """
    start = time.perf_counter()
    mods = _load_board_modules()  # antes de tocar no disco
    target = prepare_output_dir(output_dir)
    s = SimpleNamespace(
        mods=mods, public=target / "public", private=target / "private",
        tampered=target / "tampered_public",
    )
    report = DemoReport(output_dir=target, public_dir=s.public, private_dir=s.private,
                        tampered_dir=s.tampered)
    report.notes.append(
        f"parâmetros reais do projeto: grupo {GROUP.name} (p de {GROUP.p.bit_length()} bits) "
        f"e RSA-PSS de {RSA_KEY_SIZE} bits; nada foi reduzido para a demo"
    )
    report.notes.append(
        "sem prova 0/1 (ZKP) nas cédulas: o cliente honesto só cifra 0/1, mas o formato "
        "da cédula não transporta a prova e o servidor não recusa cifras de outros valores. "
        "Apuração e auditor exigem soma dos totais = nº de cédulas (pega m = 2 ou voto nos "
        "dois, sem apontar o eleitor), mas não m = -1 e m = 2 na mesma cédula "
        "(limitação documentada no README)"
    )

    for number, title, concept, expected, body in STEPS:
        step = StepReport(number, title, concept, expected)
        step_start = time.perf_counter()
        try:
            body(s, step)
            if not step.checks:
                step.check("etapa sem conferências", False)
            step.ok = not step.failed_checks
            if not step.ok:
                step.error = "divergência: " + "; ".join(step.failed_checks)
        except Exception as exc:  # erro inesperado vira etapa reprovada
            step.ok = False
            step.error = f"exceção inesperada: {type(exc).__name__}: {exc}"
            step.obtained = step.obtained or step.error
        step.elapsed = time.perf_counter() - step_start
        report.steps.append(step)
        if on_step is not None:
            on_step(step)
        if not step.ok:
            break
        if pause and number < TOTAL_STEPS:
            pause_start = time.perf_counter()
            (wait if wait is not None else input)("\n  [Enter] próxima etapa ")
            report.paused += time.perf_counter() - pause_start

    report.totals = getattr(s, "totals", None)
    report.elapsed = time.perf_counter() - start - report.paused
    return report


# =============================================================================
# Saída no terminal (só formatação)
# =============================================================================
WIDTH = 78
RULE = "═" * WIDTH


def format_header(output_dir: Path) -> str:
    return "\n".join([
        RULE,
        " URNA_ONLINE — demonstração automatizada (T15)",
        f" saída: {output_dir}  (public/, private/, tampered_public/)",
        f" cenário: {', '.join(f'{v}→{c}' for v, c in VOTE_PLAN)}",
        RULE,
    ])


def format_step(step: StepReport) -> str:
    mark = "✔" if step.ok else "✘"
    lines = [
        "",
        f"[{step.number}/{TOTAL_STEPS}] {step.title}",
    ]
    lines += textwrap.wrap(step.concept, width=WIDTH, initial_indent="  O que acontece: ",
                           subsequent_indent=" " * 18)
    lines.append(f"  Esperado: {step.expected}")
    lines += [f"    · {d}" for d in step.details]
    lines.append(f"  Obtido:   {mark} {step.obtained}   ({step.elapsed:.2f} s)")
    if not step.ok:
        lines.append(f"  ERRO: {step.error}")
    return "\n".join(lines)


def format_summary(report: DemoReport) -> str:
    lines = ["", RULE, " Resumo"]
    for step in report.steps:
        lines.append(f"  [{'✔' if step.ok else '✘'}] {step.number}. {step.title}  ({step.elapsed:.2f} s)")
    for number, title, *_ in STEPS[len(report.steps):]:
        lines.append(f"  [-] {number}. {title}  (não executada)")
    expected = ", ".join(f"{c} {n}" for c, n in report.expected_totals.items())
    obtained = ", ".join(f"{c} {n}" for c, n in report.totals.items()) if report.totals else "—"
    lines.append(f"  Totais: {obtained}   (esperado: {expected})")
    for note in report.notes:
        lines += textwrap.wrap(note, width=WIDTH, initial_indent="  Nota: ", subsequent_indent=" " * 8)
    timing = f"  Tempo de execução: {report.elapsed:.2f} s (alvo < {TIME_TARGET_S:.0f} s)"
    if report.paused:
        timing += f"; pausas: {report.paused:.1f} s"
    lines.append(timing)
    lines.append(f"  RESULTADO: {'DEMONSTRAÇÃO OK' if report.success else 'FALHOU'}")
    lines.append(RULE)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Roteiro automatizado da demonstração (T15).")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                        help="diretório recriado a cada execução (padrão: data/demo/)")
    parser.add_argument("--pause", action="store_true", help="espera Enter entre as etapas")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        # Consoles Windows antigos (cp1252) não têm ✔/✘/→: troca em vez de quebrar.
        sys.stdout.reconfigure(errors="replace")

    target = Path(args.output_dir).expanduser().resolve()
    if not fcntl_available():
        print(f"ERRO: {NO_FCNTL_MESSAGE}", file=sys.stderr)
        return EXIT_NO_FCNTL
    try:
        print(format_header(target), flush=True)
        report = run_demo(target, args.pause, on_step=lambda step: print(format_step(step), flush=True))
    except (KeyboardInterrupt, EOFError):
        # Ctrl+C em qualquer momento ou Ctrl+D no prompt do --pause (input()
        # lança EOFError). Sai sem traceback; o diretório de saída fica como
        # estava e é recriado na próxima execução.
        print(f"\n{INTERRUPTED_MESSAGE}", file=sys.stderr)
        return EXIT_INTERRUPTED
    except DemoPlatformError as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return EXIT_NO_FCNTL
    except ValueError as exc:  # diretório de saída recusado
        print(f"ERRO: {exc}", file=sys.stderr)
        return EXIT_BAD_OUTPUT_DIR
    print(format_summary(report))
    if not report.success:
        failed = next(step for step in report.steps if not step.ok)
        print(f"ERRO: a etapa {failed.number} divergiu do esperado: {failed.error}", file=sys.stderr)
        return EXIT_DIVERGED
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
