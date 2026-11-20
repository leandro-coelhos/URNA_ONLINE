"""Assinaturas RSA-PSS/SHA-256: operações básicas, sem estado eleitoral.

A chave privada é usada somente pelo participante que assina. O servidor e
o auditor verificam com a chave pública. A biblioteca RSA é permitida pelo
enunciado; não implementamos RSA manualmente nem usamos assinatura RSA sem padding.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from src.crypto.keys import load_rsa_public_key, validate_rsa_public_key


def _pss() -> padding.PSS:
    # Fixar os parâmetros evita que quem enviou a cédula escolha um algoritmo
    # mais fraco. Salt de 32 bytes = tamanho da saída SHA-256.
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def generate_signing_key(key_size: int = 3072) -> rsa.RSAPrivateKey:
    """Gera uma chave no lado do eleitor; não grava nem transmite o segredo."""
    if type(key_size) is not int or key_size not in (2048, 3072, 4096, 8192):
        raise ValueError("Use RSA de 2048, 3072, 4096 ou 8192 bits.")
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def sign_bytes(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Assina os bytes fornecidos. O chamador define a representação canônica."""
    if not isinstance(data, bytes):
        raise TypeError("A mensagem a assinar deve estar em bytes.")
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("É necessária a chave privada RSA do signatário.")
    validate_rsa_public_key(private_key.public_key())
    # A própria biblioteca calcula o SHA-256: não pré-calculamos outro hash.
    return private_key.sign(data, _pss(), hashes.SHA256())


def verify_bytes(data: bytes, signature: bytes, public_key_pem: str | bytes) -> bool:
    """Verifica a assinatura; False significa assinatura inválida.

    Tipos incorretos ou chave pública inválida levantam exceção. Não há acesso
    à chave privada, ao cadastro interno ou ao estado do servidor.
    """
    if not isinstance(data, bytes) or not isinstance(signature, bytes):
        raise TypeError("Mensagem e assinatura devem estar em bytes.")
    key = load_rsa_public_key(public_key_pem)
    try:
        key.verify(signature, data, _pss(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True
