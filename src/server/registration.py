"""Cadastro público de eleitores e autoridades (issue #4 / T05).

Este módulo recebe chaves públicas já geradas pelos participantes. Não gera,
recebe ou armazena suas chaves privadas. Os parâmetros p e q devem vir do
módulo de grupo criptográfico, previamente validados, nunca do participante.

O cadastro fica em memória. ``export_public_data`` entrega uma cópia JSON-
compatível para publicação; persistência e ciclo eleitoral serão integrados
pelo servidor. O uso previsto é sequencial, pela interface de linha de comando.
"""

from collections.abc import Callable
from dataclasses import asdict, dataclass
from math import gcd
import re

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class RegistrationError(ValueError):
    """Base dos erros de cadastro que a CLI pode apresentar ao usuário."""


class InvalidIdentifierError(RegistrationError):
    """Identificador vazio, ambíguo ou fora do formato combinado."""


class InvalidPublicKeyError(RegistrationError):
    """Chave pública malformada ou incompatível com a eleição."""


class DuplicateParticipantError(RegistrationError):
    """Identificador ou chave pública já cadastrado no mesmo papel."""


class RegistrationClosedError(RegistrationError):
    """O cadastro não está permitido na etapa atual."""


@dataclass(frozen=True)
class Voter:
    """Dados públicos imutáveis de um eleitor; PEM é um formato textual de chave."""

    voter_id: str
    public_key_pem: str


@dataclass(frozen=True)
class Authority:
    """Dados públicos de uma autoridade; h_i = g elevado a x_i, módulo p."""

    authority_id: str
    public_key: int


def _validate_identifier(identifier: str) -> None:
    # Não corrigimos silenciosamente espaços ou letras: o mesmo identificador
    # precisa ter exatamente a mesma representação no cadastro e na cédula.
    if not isinstance(identifier, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", identifier
    ):
        raise InvalidIdentifierError(
            "Use de 1 a 64 caracteres ASCII: letras, números, '_' ou '-'; "
            "o primeiro deve ser letra ou número."
        )


def _normalize_rsa_public_key(pem: str | bytes) -> str:
    """Valida a chave e padroniza a representação, sem acessar dados privados."""
    if not isinstance(pem, (str, bytes)):
        raise InvalidPublicKeyError("A chave RSA deve ser um texto PEM ou bytes.")
    if len(pem) > 16_384:
        raise InvalidPublicKeyError("O arquivo de chave pública é grande demais.")
    try:
        encoded = pem.encode("ascii") if isinstance(pem, str) else pem
    except UnicodeEncodeError as exc:
        raise InvalidPublicKeyError("O PEM deve conter somente caracteres ASCII.") from exc

    # Exigimos um único bloco público. Assim, uma chave privada ou várias
    # chaves concatenadas não são aceitas por engano como um cadastro válido.
    if not re.fullmatch(
        rb"-----BEGIN (PUBLIC KEY|RSA PUBLIC KEY)-----\r?\n"
        rb"[A-Za-z0-9+/=\r\n]+-----END \1-----",
        encoded.strip(),
    ):
        raise InvalidPublicKeyError("Forneça exatamente uma chave pública em PEM.")
    try:
        key = serialization.load_pem_public_key(encoded)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise InvalidPublicKeyError("Não foi possível ler a chave pública.") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise InvalidPublicKeyError("A chave do eleitor precisa ser RSA.")

    numbers = key.public_numbers()
    if not 2048 <= key.key_size <= 8192:
        raise InvalidPublicKeyError("A chave RSA deve ter entre 2048 e 8192 bits.")
    if numbers.e != 65537 or numbers.n % 2 == 0 or gcd(numbers.n, numbers.e) != 1:
        raise InvalidPublicKeyError("Parâmetros RSA inválidos para esta eleição.")

    # SPKI e PKCS#1 podem representar a mesma chave de maneiras distintas.
    # Converter tudo para SPKI permite detectar a reutilização dessa chave.
    return key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


class Registration:
    """Cadastro de uma eleição, independente da implementação do ciclo eleitoral.

    ``state_provider`` é uma função sem argumentos que retorna a etapa atual,
    por exemplo ``lambda: election.state``. Somente ``'CADASTRO'`` permite
    inclusões. Ao iniciar a votação, o servidor deve chamar ``freeze()``.

    ``p`` e ``q`` são primos já validados pela configuração: q é a ordem do
    subgrupo de ElGamal. Aqui verificamos coerência básica dos parâmetros e
    pertencimento das chaves ao subgrupo, não a primalidade de p e q.
    """

    def __init__(
        self,
        election_id: str,
        *,
        p: int,
        q: int,
        state_provider: Callable[[], str],
    ) -> None:
        _validate_identifier(election_id)
        # bool é uma subclasse de int em Python; type(...) evita aceitar True.
        if (
            type(p) is not int
            or type(q) is not int
            or p.bit_length() < 2048
            or q.bit_length() < 224
            or not 2 < q < p
            or p % 2 == 0
            or q % 2 == 0
            or (p - 1) % q != 0
        ):
            raise ValueError("Forneça parâmetros p e q previamente validados do grupo.")
        if not callable(state_provider):
            raise TypeError("state_provider deve ser uma função que informa a etapa.")

        self._election_id = election_id
        self._p = p
        self._q = q
        self._state_provider = state_provider
        self._frozen = False
        self._voters: dict[str, Voter] = {}
        self._authorities: dict[str, Authority] = {}

    def _require_registration_phase(self) -> None:
        if self._frozen:
            raise RegistrationClosedError("O cadastro já foi congelado.")
        state = self._state_provider()
        if state in ("VOTACAO_ABERTA", "ENCERRADA", "APURACAO", "AUDITADA"):
            # Depois de observar a votação, não reabrimos nem se o provedor
            # informar CADASTRO novamente por erro. O ciclo deve impedir esse
            # retrocesso e chamar freeze antes de abrir a votação.
            self.freeze()
        if state != "CADASTRO":
            raise RegistrationClosedError("Inclusões são permitidas somente em CADASTRO.")

    def register_voter(self, voter_id: str, public_key_pem: str | bytes) -> Voter:
        """Registra um eleitor após validar etapa, identificação e chave RSA."""
        self._require_registration_phase()
        _validate_identifier(voter_id)
        if voter_id in self._voters:
            raise DuplicateParticipantError("Identificador de eleitor já cadastrado.")
        normalized_key = _normalize_rsa_public_key(public_key_pem)
        if any(v.public_key_pem == normalized_key for v in self._voters.values()):
            raise DuplicateParticipantError("Chave RSA já vinculada a outro eleitor.")
        voter = Voter(voter_id, normalized_key)
        # Só alteramos o cadastro depois que TODAS as validações passaram.
        self._voters[voter_id] = voter
        return voter

    def register_authority(self, authority_id: str, public_key: int) -> Authority:
        """Registra h_i, nunca o segredo x_i de uma autoridade."""
        self._require_registration_phase()
        _validate_identifier(authority_id)
        if authority_id in self._authorities:
            raise DuplicateParticipantError("Identificador de autoridade já cadastrado.")
        # Excluímos a identidade 1 e elementos fora do subgrupo. Como q é primo,
        # h_i != 1 e h_i^q = 1 (mod p) garantem ordem q, sob o contrato do grupo.
        if (
            type(public_key) is not int
            or not 1 < public_key < self._p - 1
            or pow(public_key, self._q, self._p) != 1
        ):
            raise InvalidPublicKeyError("Chave de autoridade fora do subgrupo permitido.")
        if any(a.public_key == public_key for a in self._authorities.values()):
            raise DuplicateParticipantError("Chave pública já vinculada a outra autoridade.")
        authority = Authority(authority_id, public_key)
        self._authorities[authority_id] = authority
        return authority

    def get_voter(self, voter_id: str) -> Voter:
        """Consulta um eleitor; KeyError indica que ele não foi cadastrado."""
        return self._voters[voter_id]

    def get_authority(self, authority_id: str) -> Authority:
        """Consulta uma autoridade; KeyError indica identificação desconhecida."""
        return self._authorities[authority_id]

    def freeze(self) -> None:
        """Bloqueia definitivamente inclusões nesta instância; consultas continuam."""
        self._frozen = True

    def export_public_data(self) -> dict:
        """Entrega uma cópia dos dados públicos, serializável com json.dumps.

        Não é uma prova de autenticidade: o protocolo ainda precisa autenticar
        e preservar o cadastro fechado para o auditor detectar substituições.
        """
        return {
            "schema_version": 1,
            "election_id": self._election_id,
            "frozen": self._frozen,
            "voters": [asdict(v) for v in self._voters.values()],
            "authorities": [
                # Strings decimais preservam inteiros grandes em leitores JSON
                # que, ao contrário do Python, usam números de precisão limitada.
                {"authority_id": a.authority_id, "public_key": str(a.public_key)}
                for a in self._authorities.values()
            ],
        }
