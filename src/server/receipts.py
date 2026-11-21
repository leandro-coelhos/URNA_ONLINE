"""Emissão do recibo depois da gravação no quadro (#6 / T09).

O controlador eleitoral deve validar etapa e provas ANTES de chamar
publish_with_receipt. A função integra publicação da #8 e assinatura da #6,
sem implementar as regras do ciclo eleitoral da #5.

O servidor mantém uma chave RSA própria, separada das chaves dos eleitores
e dos segredos ElGamal das autoridades. Sua chave pública deve ser fixada e
autenticada na configuração. Este módulo não gera nem persiste chaves.
"""

from copy import deepcopy

from cryptography.hazmat.primitives.asymmetric import rsa

from src.bulletin_board.board import BulletinBoard
from src.crypto.keys import validate_rsa_public_key
from src.crypto.receipts import ReceiptNotFoundError, sign_receipt


class ReceiptIssuanceError(RuntimeError):
    """O registro existe no quadro, mas a assinatura do recibo falhou.

    accepted_record é uma cópia dos dados públicos já gravados. Não reenviar
    o voto: após resolver a falha, use issue_receipt para recuperar o recibo.
    """

    def __init__(self, record: dict):
        super().__init__("Cédula registrada, mas o recibo não pôde ser assinado. Recupere o recibo.")
        self.accepted_record = deepcopy(record)


def _sign_accepted_record(record: dict, server_private_key: rsa.RSAPrivateKey) -> dict:
    try:
        return sign_receipt(record, server_private_key)
    except Exception as exc:
        # A gravação já terminou. Não transformar falha de assinatura em uma
        # suposta rejeição do voto, nem apagar um registro do quadro append-only.
        raise ReceiptIssuanceError(record) from exc


def publish_with_receipt(
    board: BulletinBoard, envelope: dict, *, server_private_key: rsa.RSAPrivateKey,
) -> dict:
    """Publica a cédula e devolve o recibo somente após append ter sucesso.

    Valida a chave antes de gravar para evitar erros de configuração comuns.
    Se append falhar, propaga o erro e não assina recibo. Uma falha de I/O
    pode deixar bytes no disco: deve ser tratada conforme o contrato da #8.
    A entrega do recibo ao eleitor não é uma transação com a gravação.
    """
    if not isinstance(server_private_key, rsa.RSAPrivateKey):
        raise TypeError("É necessária a chave privada RSA do servidor.")
    validate_rsa_public_key(server_private_key.public_key())
    record = board.append(envelope)
    return _sign_accepted_record(record, server_private_key)


def issue_receipt(
    board: BulletinBoard, *, voter_id: str, server_private_key: rsa.RSAPrivateKey,
) -> dict:
    """Emite ou recupera recibo de uma cédula JÁ registrada, sem novo voto.

    Relê e verifica o quadro completo contra o checkpoint desta instância.
    Ao reabrir o quadro, o controlador deve fornecer um checkpoint confiável.
    PSS é aleatório: nova assinatura pode diferir, mas o corpo é o mesmo.
    """
    for record in board.records():
        if record["ballot"]["voter_id"] == voter_id:
            return _sign_accepted_record(record, server_private_key)
    raise ReceiptNotFoundError("Eleitor não possui cédula no quadro verificado.")
