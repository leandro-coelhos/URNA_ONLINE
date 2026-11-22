"""Formato público e verificador da #8, sem dependência de src.server.

Hashes não autenticam, sozinhos, o histórico escolhido pelo administrador.
O verificador exige um checkpoint obtido de uma fonte independente confiável.
Ele verifica um retrato exato do quadro, não declara toda a eleição válida.
"""

from collections.abc import Iterable, Mapping, Sequence
import hashlib
import json
import re
from typing import BinaryIO

from src.crypto.ballots import MAX_CANDIDATES, load_signed_ballot, verify_signed_ballot
from src.crypto.keys import normalize_rsa_public_key


GENESIS_DOMAIN = b"URNA_ONLINE:BOARD:GENESIS:v1\x00"
RECORD_DOMAIN = b"URNA_ONLINE:BOARD:RECORD:v1\x00"
MAX_RECORD_BYTES = 1_048_576  # Inclui a quebra de linha do arquivo JSONL.
BODY_FIELDS = {"schema_version", "index", "previous_hash", "ballot", "signature"}


class BoardError(ValueError):
    """Base dos erros do quadro público."""


class BoardFormatError(BoardError):
    """Documento não corresponde ao formato público esperado."""


class ChainIntegrityError(BoardError):
    """Hash, posição, elo ou checkpoint não corresponde ao histórico esperado."""


class DuplicateVoteError(BoardError):
    """O mesmo eleitor aparece mais de uma vez no quadro."""


def _identifier(value: str) -> None:
    # Mesma política dos contratos de cadastro e cédulas das issues #4 e #7.
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value):
        raise BoardFormatError("Identificador inválido na configuração do quadro.")


def _hash(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise BoardFormatError("Hash deve conter 64 caracteres hexadecimais minúsculos.")


def _natural(value: int) -> None:
    # bool também é int em Python; a comparação exata de tipo rejeita True/False.
    if type(value) is not int or not 0 <= value < 2**63:
        raise BoardFormatError("Índice ou tamanho deve ser inteiro entre 0 e 2**63 - 1.")


def _json_bytes(value: dict) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise BoardFormatError("Não foi possível representar o registro como JSON.") from exc


def validate_public_context(
    *, election_id: str, candidate_ids: Sequence[str], voter_public_keys: Mapping[str, str | bytes]
) -> dict:
    """Valida e copia a configuração; sua autenticidade depende do protocolo.

    A cópia impede que editar o dicionário original mude o cadastro de uma
    instância já aberta. Não cria cadastro, chaves privadas ou candidatos.
    """
    _identifier(election_id)
    if isinstance(candidate_ids, (str, bytes)) or not isinstance(candidate_ids, Sequence):
        raise BoardFormatError("Forneça uma sequência de candidatos.")
    candidates = tuple(candidate_ids)
    if not 2 <= len(candidates) <= MAX_CANDIDATES:
        raise BoardFormatError("Configuração deve conter de 2 a 128 candidatos.")
    for candidate_id in candidates:
        _identifier(candidate_id)
    if len(set(candidates)) != len(candidates):
        raise BoardFormatError("Candidatos repetidos na configuração.")
    if not isinstance(voter_public_keys, Mapping):
        raise BoardFormatError("Forneça um mapa de eleitores e chaves públicas.")
    keys = {}
    for voter_id, pem in voter_public_keys.items():
        _identifier(voter_id)
        keys[voter_id] = normalize_rsa_public_key(pem)
    if len(set(keys.values())) != len(keys):
        raise BoardFormatError("A mesma chave RSA não pode identificar dois eleitores.")
    return {"election_id": election_id, "candidate_ids": candidates, "voter_public_keys": keys}


def genesis_hash(election_id: str) -> str:
    """Define o elo inicial, diferente para cada identificador de eleição."""
    _identifier(election_id)
    return hashlib.sha256(GENESIS_DOMAIN + election_id.encode("ascii")).hexdigest()


def make_checkpoint(*, election_id: str, size: int, head_hash: str) -> dict:
    """Resumo público de um retrato. Construí-lo NÃO o torna confiável."""
    _identifier(election_id)
    _natural(size)
    _hash(head_hash)
    if size == 0 and head_hash != genesis_hash(election_id):
        raise ChainIntegrityError("Quadro vazio deve apontar para o hash inicial.")
    return {"schema_version": 1, "election_id": election_id, "size": size, "head_hash": head_hash}


def _validate_checkpoint(checkpoint: dict, election_id: str) -> None:
    if type(checkpoint) is not dict or set(checkpoint) != {
        "schema_version", "election_id", "size", "head_hash"
    }:
        raise BoardFormatError("Checkpoint deve conter versão, eleição, tamanho e hash final.")
    if type(checkpoint["schema_version"]) is not int or checkpoint["schema_version"] != 1:
        raise BoardFormatError("Versão de checkpoint não suportada.")
    if checkpoint["election_id"] != election_id:
        raise ChainIntegrityError("Checkpoint pertence a outra eleição.")
    make_checkpoint(
        election_id=election_id, size=checkpoint["size"], head_hash=checkpoint["head_hash"]
    )


def hash_record(body: dict) -> str:
    """SHA-256 do domínio e do corpo canônico, SEM o próprio campo hash.

    Valida formato, não assinatura/eligibilidade. Qualquer pessoa consegue
    recalcular hashes; essa função também é útil para demonstrar esse ataque.
    """
    if type(body) is not dict or set(body) != BODY_FIELDS:
        raise BoardFormatError("Campos ausentes ou extras no corpo do registro.")
    if type(body["schema_version"]) is not int or body["schema_version"] != 1:
        raise BoardFormatError("Versão de registro não suportada.")
    _natural(body["index"])
    _hash(body["previous_hash"])
    # Reutiliza o contrato estrito da #7, sem importar funções privadas dela.
    load_signed_ballot(_json_bytes({"ballot": body["ballot"], "signature": body["signature"]}))
    canonical = _json_bytes(body)
    # Reserva espaço para ,"hash":"<64 caracteres>" e para a quebra de linha.
    if len(canonical) + 75 > MAX_RECORD_BYTES:
        raise BoardFormatError("Registro ultrapassa o limite de 1 MiB.")
    return hashlib.sha256(RECORD_DOMAIN + canonical).hexdigest()


def make_record(envelope: dict, *, index: int, previous_hash: str) -> dict:
    """Monta uma cópia do registro. A aceitação ainda exige verify_signed_ballot."""
    copied = load_signed_ballot(_json_bytes(envelope))
    body = {"schema_version": 1, "index": index, "previous_hash": previous_hash, **copied}
    return {**body, "hash": hash_record(body)}


def _verify_record_hash(record: dict) -> None:
    if type(record) is not dict or set(record) != BODY_FIELDS | {"hash"}:
        raise BoardFormatError("Campos ausentes ou extras no registro público.")
    _hash(record["hash"])
    body = {key: value for key, value in record.items() if key != "hash"}
    if record["hash"] != hash_record(body):
        raise ChainIntegrityError("Conteúdo do registro não corresponde ao seu hash.")


def encode_record(record: dict) -> bytes:
    """Uma linha JSONL canônica, já terminada por LF (byte 10)."""
    _verify_record_hash(record)
    return _json_bytes(record) + b"\n"


def _unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise BoardFormatError("JSON contém campo repetido.")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise BoardFormatError("JSON não admite NaN ou Infinity.")


def read_records(stream: BinaryIO) -> Iterable[dict]:
    """Lê JSONL binário com limite por linha e sem JSON ambíguo.

    Não ignora linhas vazias ou um final incompleto. Não verifica a cadeia:
    passe o iterador para verify_board, com configuração e checkpoint confiáveis.
    """
    while True:
        line = stream.readline(MAX_RECORD_BYTES + 1)
        if not line:
            return
        if not isinstance(line, bytes):
            raise BoardFormatError("Abra o quadro em modo binário: rb.")
        if len(line) > MAX_RECORD_BYTES or not line.endswith(b"\n"):
            raise BoardFormatError("Linha muito grande ou incompleta no quadro público.")
        try:
            record = json.loads(
                line.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant
            )
        except (UnicodeError, ValueError, RecursionError) as exc:
            if isinstance(exc, BoardFormatError):
                raise
            raise BoardFormatError("Linha JSON inválida no quadro público.") from exc
        if type(record) is not dict:
            raise BoardFormatError("Cada linha deve conter um objeto JSON.")
        yield record


def verify_board(
    records: Iterable[dict], *, election_id: str, candidate_ids: Sequence[str],
    voter_public_keys: Mapping[str, str | bytes], expected_checkpoint: dict,
) -> dict:
    """Verifica um retrato EXATO do quadro usando somente dados públicos.

    O checkpoint esperado é obrigatório e deve ter sido preservado fora do
    controle do administrador. Obtê-lo do mesmo arquivo suspeito anula essa
    proteção. Não verifica provas ElGamal, estado eleitoral, apuração ou recibos.
    """
    context = validate_public_context(
        election_id=election_id, candidate_ids=candidate_ids, voter_public_keys=voter_public_keys
    )
    _validate_checkpoint(expected_checkpoint, election_id)
    previous_hash = genesis_hash(election_id)
    seen = set()
    size = 0
    for record in records:
        _verify_record_hash(record)
        if record["index"] != size or record["previous_hash"] != previous_hash:
            raise ChainIntegrityError("Índice ou elo anterior quebra a sequência do quadro.")
        ballot = verify_signed_ballot(
            {"ballot": record["ballot"], "signature": record["signature"]}, **context
        )
        voter_id = ballot["voter_id"]
        if voter_id in seen:
            raise DuplicateVoteError("Eleitor repetido no quadro público.")
        seen.add(voter_id)
        previous_hash = record["hash"]
        size += 1
    actual = make_checkpoint(election_id=election_id, size=size, head_hash=previous_hash)
    if actual != expected_checkpoint:
        raise ChainIntegrityError("Quadro diverge do tamanho ou hash do checkpoint esperado.")
    return actual
