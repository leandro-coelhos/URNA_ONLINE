"""Formato canônico e autenticação de cédulas cifradas (issue #7 / T06).

Usável pelo eleitor, servidor e auditor, sem importar src.server. Esta etapa
verifica formato, contexto, elegibilidade no cadastro fornecido e assinatura.
Não verifica provas de bit, pertencimento das cifras ao grupo, duplicidade de
voto ou a etapa da eleição: essas verificações pertencem aos outros módulos.
"""

import base64
import binascii
from collections.abc import Mapping, Sequence
import json
import re

from cryptography.hazmat.primitives.asymmetric import rsa

from src.crypto.signatures import sign_bytes, verify_bytes


# Separação de domínio: os mesmos bytes não podem ser reutilizados como uma
# assinatura de recibo ou outro documento que use um domínio diferente.
BALLOT_DOMAIN = b"URNA_ONLINE:BALLOT:v1\x00"
MAX_JSON_BYTES = 1_048_576
MAX_CANDIDATES = 128  # Mesmo no tamanho máximo das cifras, o envelope cabe em 1 MiB.
MAX_CIPHERTEXT_DIGITS = 2500  # Comporta componentes de grupos de até 8192 bits.


class BallotError(ValueError):
    """Base dos erros de autenticação de cédulas."""


class BallotFormatError(BallotError):
    """Estrutura não corresponde ao esquema público da versão 1."""


class IneligibleVoterError(BallotError):
    """Identificador não consta no cadastro público fornecido."""


class InvalidBallotSignatureError(BallotError):
    """Assinatura não corresponde à cédula e à chave cadastrada."""


def _require_identifier(value: str) -> None:
    # Mesma política de identificadores da #4: não normalizar dados assinados.
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value):
        raise BallotFormatError("Identificador inválido na cédula ou configuração.")


def canonical_ballot_bytes(ballot: dict) -> bytes:
    """Valida o esquema e produz os bytes JSON exatos a serem assinados.

    A ordem das chaves de objetos é normalizada; a ordem dos candidatos na
    lista é preservada e faz parte da mensagem. Valores cifrados são strings
    decimais positivas, sem sinal, espaços ou zeros à esquerda.
    """
    if type(ballot) is not dict or set(ballot) != {
        "schema_version", "election_id", "voter_id", "ciphertexts"
    }:
        raise BallotFormatError("Campos obrigatórios ausentes ou campos extras na cédula.")
    if type(ballot["schema_version"]) is not int or ballot["schema_version"] != 1:
        raise BallotFormatError("Versão de cédula não suportada.")
    _require_identifier(ballot["election_id"])
    _require_identifier(ballot["voter_id"])
    ciphertexts = ballot["ciphertexts"]
    if type(ciphertexts) is not list or not 2 <= len(ciphertexts) <= MAX_CANDIDATES:
        raise BallotFormatError("A cédula deve conter de 2 a 128 candidatos.")

    seen = set()
    for ciphertext in ciphertexts:
        if type(ciphertext) is not dict or set(ciphertext) != {"candidate_id", "c1", "c2"}:
            raise BallotFormatError("Cada cifra precisa de candidate_id, c1 e c2, sem extras.")
        candidate_id = ciphertext["candidate_id"]
        _require_identifier(candidate_id)
        if candidate_id in seen:
            raise BallotFormatError("Candidato repetido na cédula.")
        seen.add(candidate_id)
        for component in (ciphertext["c1"], ciphertext["c2"]):
            if (
                not isinstance(component, str)
                or not 1 <= len(component) <= MAX_CIPHERTEXT_DIGITS
                or not re.fullmatch(r"[1-9][0-9]*", component)
            ):
                raise BallotFormatError("Componentes cifrados devem ser strings decimais positivas.")

    # Como o esquema só admite identificadores ASCII, strings decimais e a
    # versão inteira 1, não há floats, NaN ou normalização Unicode ambígua.
    return json.dumps(
        ballot, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _signature_bytes(envelope: dict) -> bytes:
    if type(envelope) is not dict or set(envelope) != {"ballot", "signature"}:
        raise BallotFormatError("O envelope deve conter somente ballot e signature.")
    encoded = envelope["signature"]
    if not isinstance(encoded, str) or not 1 <= len(encoded) <= 1368:
        raise BallotFormatError("Assinatura Base64 vazia ou grande demais.")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise BallotFormatError("Assinatura não está em Base64 válido.") from exc
    # Exigir a representação canônica evita aliases do mesmo valor em Base64.
    if base64.b64encode(signature).decode("ascii") != encoded:
        raise BallotFormatError("Use a representação Base64 canônica da assinatura.")
    return signature


def sign_ballot(ballot: dict, private_key: rsa.RSAPrivateKey) -> dict:
    """Operação do eleitor: assina as cifras prontas e devolve um envelope novo."""
    canonical = canonical_ballot_bytes(ballot)
    signature = sign_bytes(BALLOT_DOMAIN + canonical, private_key)
    # A cópia evita que o chamador altere o envelope ao editar a entrada depois.
    return {
        "ballot": json.loads(canonical),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_signed_ballot(
    envelope: dict,
    *,
    election_id: str,
    candidate_ids: Sequence[str],
    voter_public_keys: Mapping[str, str | bytes],
) -> dict:
    """Verifica usando SOMENTE o contexto e o cadastro públicos de confiança.

    Devolve uma cópia da cédula autenticada ou lança erro. Aceitar/publicar o
    voto exige as demais verificações do servidor. O auditor pode usar esta
    mesma função com uma cópia autenticada do cadastro público.
    """
    signature = _signature_bytes(envelope)
    canonical = canonical_ballot_bytes(envelope["ballot"])
    ballot = json.loads(canonical)
    _require_identifier(election_id)
    if ballot["election_id"] != election_id:
        raise BallotError("Cédula pertence a outra eleição.")
    if isinstance(candidate_ids, (str, bytes)) or not isinstance(candidate_ids, Sequence):
        raise BallotFormatError("Forneça a sequência de identificadores dos candidatos.")
    expected = list(candidate_ids)
    if not 2 <= len(expected) <= MAX_CANDIDATES:
        raise BallotFormatError("Configuração deve conter de 2 a 128 candidatos.")
    for candidate_id in expected:
        _require_identifier(candidate_id)
    if len(set(expected)) != len(expected):
        raise BallotFormatError("Configuração contém candidatos repetidos.")
    if [c["candidate_id"] for c in ballot["ciphertexts"]] != expected:
        raise BallotError("Candidatos ou ordem não correspondem à eleição.")
    if not isinstance(voter_public_keys, Mapping):
        raise TypeError("O cadastro público deve mapear identificadores a chaves PEM.")
    try:
        public_key = voter_public_keys[ballot["voter_id"]]
    except KeyError as exc:
        raise IneligibleVoterError("Eleitor não cadastrado nesta eleição.") from exc
    if not verify_bytes(BALLOT_DOMAIN + canonical, signature, public_key):
        raise InvalidBallotSignatureError("Assinatura inválida ou cédula alterada.")
    return ballot


def _unique_object(pairs: list[tuple]) -> dict:
    # json.loads normalmente mantém o último valor de uma chave repetida.
    # No protocolo, rejeitamos essa ambiguidade em qualquer nível do JSON.
    result = {}
    for key, value in pairs:
        if key in result:
            raise BallotFormatError("JSON contém campo repetido.")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise BallotFormatError("JSON não admite NaN ou Infinity neste protocolo.")


def load_signed_ballot(document: str | bytes) -> dict:
    """Lê um envelope JSON da rede/arquivo sem aceitar campos duplicados.

    Verifica o formato, mas NÃO a assinatura: chame verify_signed_ballot em
    seguida. O limite de tamanho também deve ser aplicado ao ler da rede/disco.
    """
    if not isinstance(document, (str, bytes)):
        raise BallotFormatError("Forneça o documento JSON como texto ou bytes UTF-8.")
    if len(document) > MAX_JSON_BYTES:
        raise BallotFormatError("Documento JSON grande demais.")
    try:
        encoded = document.encode("utf-8") if isinstance(document, str) else document
        if len(encoded) > MAX_JSON_BYTES:
            raise BallotFormatError("Documento JSON grande demais.")
        result = json.loads(
            encoded.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, BallotFormatError):
            raise
        raise BallotFormatError("Documento JSON inválido.") from exc
    _signature_bytes(result)
    canonical_ballot_bytes(result["ballot"])
    return result
