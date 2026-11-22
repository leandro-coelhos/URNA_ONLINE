"""Formato público e verificação de recibos assinados (#6 / T09).

Envelope JSON v1: {"receipt": {...}, "signature": "<Base64>"}.
O corpo contém EXATAMENTE schema_version=1, election_id, voter_id,
record_index (inteiro desde 0) e record_hash (SHA-256 hexadecimal minúsculo).
Assinatura: RSA-PSS/SHA-256, MGF1/SHA-256 e salt de 32 bytes, como na #7,
mas com domínio próprio. A chave pública do servidor vem da configuração
autenticada da eleição, nunca do próprio comprovante.

sign_receipt é uma primitiva: não comprova persistência nem aceitação.
O servidor deve usar src.server.receipts, que opera sobre o quadro gravado.
A verificação pública daqui não importa src.server nem recebe segredos.

O recibo autentica a declaração do servidor. Para conferir inclusão, use
verify_receipt_in_board com o envelope originalmente enviado pelo eleitor,
dados públicos confiáveis e um checkpoint preservado independentemente.
Ele não prova validade dos bits, justiça, resultado ou ausência de coerção.
Não contém voto em claro ou r; revelar r junto da cifra pode provar o voto.
"""

import base64
import binascii
from collections.abc import Iterable, Mapping, Sequence
from copy import deepcopy
import json
import re

from cryptography.hazmat.primitives.asymmetric import rsa

from src.bulletin_board.hash_chain import encode_record, verify_board
from src.crypto.ballots import verify_signed_ballot
from src.crypto.signatures import sign_bytes, verify_bytes


RECEIPT_DOMAIN = b"URNA_ONLINE:RECEIPT:v1\x00"
MAX_RECEIPT_BYTES = 4096  # Comporta o esquema mesmo com assinatura RSA de 8192 bits.


class ReceiptError(ValueError):
    """Base dos erros de formato, autenticação ou inclusão do recibo."""


class ReceiptFormatError(ReceiptError):
    """Documento fora do esquema público ou JSON ambíguo."""


class InvalidReceiptSignatureError(ReceiptError):
    """Assinatura não corresponde ao servidor e ao conteúdo recebido."""


class ReceiptMismatchError(ReceiptError):
    """Eleição, eleitor ou registro diverge do que o eleitor esperava."""


class ReceiptNotFoundError(ReceiptError):
    """Registro referenciado não foi encontrado no quadro verificado."""


def _identifier(value: str) -> None:
    # Mesma política das #4, #7 e #8, sem normalizar o conteúdo assinado.
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value):
        raise ReceiptFormatError("Identificador inválido no recibo ou no contexto esperado.")


def canonical_receipt_bytes(receipt: dict) -> bytes:
    """Valida e serializa somente o corpo, em JSON ASCII sem espaços.

    Campos extras são rejeitados, inclusive chaves, timestamps, escolhas e
    aleatoriedade. A ordem das chaves do dicionário não altera a assinatura.
    """
    if type(receipt) is not dict or set(receipt) != {
        "schema_version", "election_id", "voter_id", "record_index", "record_hash"
    }:
        raise ReceiptFormatError("Campos ausentes ou extras no recibo.")
    if type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1:
        raise ReceiptFormatError("Versão de recibo não suportada.")
    _identifier(receipt["election_id"])
    _identifier(receipt["voter_id"])
    index = receipt["record_index"]
    # bool herda de int: type(...) is int impede aceitar True como índice 1.
    if type(index) is not int or not 0 <= index < 2**63:
        raise ReceiptFormatError("Índice deve ser inteiro entre 0 e 2**63 - 1.")
    digest = receipt["record_hash"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ReceiptFormatError("Hash deve ter 64 caracteres hexadecimais minúsculos.")
    return json.dumps(
        receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _signature_bytes(envelope: dict) -> bytes:
    if type(envelope) is not dict or set(envelope) != {"receipt", "signature"}:
        raise ReceiptFormatError("Envelope deve conter somente receipt e signature.")
    encoded = envelope["signature"]
    if not isinstance(encoded, str) or not 1 <= len(encoded) <= 1368:
        raise ReceiptFormatError("Assinatura Base64 vazia ou grande demais.")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ReceiptFormatError("Assinatura não está em Base64 válido.") from exc
    if base64.b64encode(signature).decode("ascii") != encoded:
        raise ReceiptFormatError("Use a representação Base64 canônica da assinatura.")
    return signature


def sign_receipt(record: dict, private_key: rsa.RSAPrivateKey) -> dict:
    """Assina uma referência a um registro previamente aceito pelo servidor.

    Confere formato e hash do registro por encode_record, mas essa checagem
    sozinha NÃO verifica assinatura do eleitor, cadeia ou gravação no disco.
    O corpo é derivado do registro; não recebe campos livres do eleitor.
    """
    encode_record(record)
    receipt = {
        "schema_version": 1,
        "election_id": record["ballot"]["election_id"],
        "voter_id": record["ballot"]["voter_id"],
        "record_index": record["index"],
        "record_hash": record["hash"],
    }
    canonical = canonical_receipt_bytes(receipt)
    signature = sign_bytes(RECEIPT_DOMAIN + canonical, private_key)
    return {"receipt": json.loads(canonical), "signature": base64.b64encode(signature).decode("ascii")}


def verify_signed_receipt(
    envelope: dict, *, election_id: str, voter_id: str, server_public_key_pem: str | bytes,
) -> dict:
    """Autentica a declaração do servidor e devolve uma cópia do corpo.

    Eleição, eleitor e chave esperados são entradas do verificador. Não os
    extraia do documento suspeito para estabelecer sua própria confiança.
    A assinatura válida ainda não comprova inclusão no quadro público.
    """
    signature = _signature_bytes(envelope)
    canonical = canonical_receipt_bytes(envelope["receipt"])
    receipt = json.loads(canonical)
    _identifier(election_id)
    _identifier(voter_id)
    if receipt["election_id"] != election_id or receipt["voter_id"] != voter_id:
        raise ReceiptMismatchError("Recibo pertence a outra eleição ou a outro eleitor.")
    if not verify_bytes(RECEIPT_DOMAIN + canonical, signature, server_public_key_pem):
        raise InvalidReceiptSignatureError("Recibo alterado ou assinatura do servidor inválida.")
    return receipt


def _unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptFormatError("JSON contém campo repetido.")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ReceiptFormatError("JSON não admite NaN ou Infinity.")


def load_signed_receipt(document: str | bytes) -> dict:
    """Lê JSON UTF-8 de até 4096 bytes; valida formato, NÃO a assinatura.

    Para dados externos, leia no máximo MAX_RECEIPT_BYTES + 1 bytes antes
    desta chamada; o limite aqui não impede uma leitura ilimitada anterior.
    """
    if not isinstance(document, (str, bytes)) or len(document) > MAX_RECEIPT_BYTES:
        raise ReceiptFormatError("Forneça JSON em texto/bytes de até 4096 bytes.")
    try:
        encoded = document.encode("utf-8") if isinstance(document, str) else document
        if len(encoded) > MAX_RECEIPT_BYTES:
            raise ReceiptFormatError("Documento JSON grande demais.")
        envelope = json.loads(
            encoded.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, ReceiptFormatError):
            raise
        raise ReceiptFormatError("Documento JSON inválido.") from exc
    _signature_bytes(envelope)
    canonical_receipt_bytes(envelope["receipt"])
    return envelope


def verify_receipt_in_board(
    envelope: dict, records: Iterable[dict], *, submitted_envelope: dict,
    election_id: str, voter_id: str, server_public_key_pem: str | bytes,
    candidate_ids: Sequence[str], voter_public_keys: Mapping[str, str | bytes],
    expected_checkpoint: dict,
) -> dict:
    """Confere recibo, quadro COMPLETO e a cédula guardada pelo eleitor.

    Retorna o registro correspondente ou lança erro. Usa somente dados
    públicos, inclusive o envelope local originalmente enviado. Conferir
    esse envelope impede aceitar outra cédula assinada pelo mesmo eleitor.
    Não para ao localizar o índice: adulteração posterior também deve falhar.
    Um recibo antigo continua útil após novos acréscimos, usando um checkpoint
    confiável do quadro atual. O recibo não é o checkpoint final da eleição.
    """
    receipt = verify_signed_receipt(
        envelope, election_id=election_id, voter_id=voter_id,
        server_public_key_pem=server_public_key_pem,
    )
    submitted = deepcopy(submitted_envelope)
    ballot = verify_signed_ballot(
        submitted, election_id=election_id, candidate_ids=candidate_ids,
        voter_public_keys=voter_public_keys,
    )
    if ballot["voter_id"] != voter_id:
        raise ReceiptMismatchError("Cédula guardada pertence a outro eleitor.")
    found = None

    def observe():
        nonlocal found
        for position, record in enumerate(records):
            # A posição é do iterador. O índice declarado ainda será verificado
            # por verify_board, assim como o hash, os elos e as assinaturas.
            if position == receipt["record_index"]:
                found = deepcopy(record)
            yield record

    verify_board(
        observe(), election_id=election_id, candidate_ids=candidate_ids,
        voter_public_keys=voter_public_keys, expected_checkpoint=expected_checkpoint,
    )
    if found is None:
        raise ReceiptNotFoundError("Registro do recibo ausente no quadro verificado.")
    if (
        found["hash"] != receipt["record_hash"]
        or found["ballot"] != ballot
        or found["signature"] != submitted["signature"]
    ):
        raise ReceiptMismatchError("Registro diverge do recibo ou da cédula originalmente enviada.")
    return found
