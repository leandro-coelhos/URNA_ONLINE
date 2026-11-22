"""Leitura e política de chaves públicas RSA, sem dependência do servidor."""

from math import gcd
import re

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class PublicKeyError(ValueError):
    """Chave incompatível com o formato ou a política RSA do projeto."""


def validate_rsa_public_key(key: rsa.RSAPublicKey) -> None:
    """Aplica a mesma política no cadastro, na assinatura e na verificação."""
    if not isinstance(key, rsa.RSAPublicKey):
        raise PublicKeyError("A chave do eleitor precisa ser RSA.")
    numbers = key.public_numbers()
    if not 2048 <= key.key_size <= 8192:
        raise PublicKeyError("A chave RSA deve ter entre 2048 e 8192 bits.")
    if numbers.e != 65537 or numbers.n % 2 == 0 or gcd(numbers.n, numbers.e) != 1:
        raise PublicKeyError("Parâmetros RSA inválidos para esta eleição.")


def load_rsa_public_key(pem: str | bytes) -> rsa.RSAPublicKey:
    """Lê exatamente um bloco público PEM; nunca carrega uma chave privada."""
    if not isinstance(pem, (str, bytes)):
        raise PublicKeyError("A chave RSA deve ser um texto PEM ou bytes.")
    if len(pem) > 16_384:
        raise PublicKeyError("O arquivo de chave pública é grande demais.")
    try:
        encoded = pem.encode("ascii") if isinstance(pem, str) else pem
    except UnicodeEncodeError as exc:
        raise PublicKeyError("O PEM deve conter somente caracteres ASCII.") from exc

    # Um único cabeçalho/rodapé correspondente evita entradas ambíguas e a
    # inclusão acidental de segredos. A biblioteca valida a estrutura interna.
    if not re.fullmatch(
        rb"-----BEGIN (PUBLIC KEY|RSA PUBLIC KEY)-----\r?\n"
        rb"[A-Za-z0-9+/=\r\n]+-----END \1-----",
        encoded.strip(),
    ):
        raise PublicKeyError("Forneça exatamente uma chave pública em PEM.")
    try:
        key = serialization.load_pem_public_key(encoded)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise PublicKeyError("Não foi possível ler a chave pública.") from exc
    validate_rsa_public_key(key)
    return key


def public_key_to_pem(key: rsa.RSAPublicKey) -> str:
    """Serializa uma chave pública válida sempre em PEM/SPKI."""
    validate_rsa_public_key(key)
    return key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def normalize_rsa_public_key(pem: str | bytes) -> str:
    """Faz SPKI e PKCS#1 da mesma chave resultarem no mesmo texto."""
    return public_key_to_pem(load_rsa_public_key(pem))
