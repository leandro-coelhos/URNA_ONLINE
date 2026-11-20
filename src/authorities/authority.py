"""Autoridades eleitorais: parcelas da chave privada e chave pública conjunta.

Cada autoridade gera sua própria chave privada ``x_i`` e publica apenas
``h_i = g^{x_i} mod p``. A chave privada fica exclusivamente em
``data/private/authority_{id}.key`` e dentro do objeto ``Authority`` daquela
autoridade; para fora sai somente ``AuthorityPublicKey`` (id, h_i).

O cadastro das chaves públicas é feito pelo ``Registration`` oficial de
``src/server/registration.py``. Este módulo consome o dicionário de
``Registration.export_public_data()`` para calcular ``h = Π h_i mod p`` e
publicá-lo em ``data/public/election.json``. Em nenhum ponto ``Σ x_i`` é
calculado ou armazenado.

Primitivas criptográficas NÃO são implementadas aqui: a exponenciação modular
vem de ``src.crypto.group.mod_exp`` (módulo mantido por outro integrante).
"""

from __future__ import annotations

import copy
import json
import os
import re
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from src.crypto.group import mod_exp

DEFAULT_PRIVATE_DIR = Path("data/private")
DEFAULT_ELECTION_PATH = Path("data/public/election.json")
KEY_FILE_VERSION = 2

# Critério de aceitação: a eleição exige pelo menos três autoridades.
MIN_AUTHORITIES = 3

# Mesma regra de src/server/registration.py (_validate_identifier).
AUTHORITY_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


class JointKeyError(ValueError):
    """Dados públicos insuficientes ou inconsistentes para a chave conjunta."""


@runtime_checkable
class GroupParams(Protocol):
    """Interface mínima esperada dos parâmetros de ``src/crypto/group.py``.

    ``p`` é um primo seguro (``p = 2q + 1``), ``q`` é a ordem do subgrupo e
    ``g`` gera esse subgrupo. Qualquer objeto com esses três atributos
    inteiros é aceito (dataclass, namedtuple, SimpleNamespace…).
    """

    p: int
    q: int
    g: int


# --------------------------------------------------------------------- validação
def validate_authority_id(authority_id: str) -> None:
    if not isinstance(authority_id, str) or not AUTHORITY_ID_PATTERN.fullmatch(authority_id):
        raise ValueError(
            "authority_id deve ter de 1 a 64 caracteres ASCII:"
            "o primeiro deve ser letra ou número."
        )


def _check_group(group: GroupParams) -> None:
    if not isinstance(group, GroupParams):
        raise TypeError("group deve expor os atributos inteiros p, q e g")
    if group.q < 3:
        raise ValueError("q pequeno demais para gerar x_i em [2, q-1]")


def _group_dict(group: GroupParams) -> dict:
    return {"p": group.p, "q": group.q, "g": group.g}


# ----------------------------------------------------------------- chave pública
@dataclass(frozen=True)
class AuthorityPublicKey:
    """Única informação de uma autoridade que pode sair do seu processo. """

    authority_id: str
    h: int

    def __post_init__(self) -> None:
        validate_authority_id(self.authority_id)
        if type(self.h) is not int:
            raise TypeError("h deve ser int")


def key_path(authority_id: str, private_dir: Path | str = DEFAULT_PRIVATE_DIR) -> Path:
    """Caminho do arquivo privado. O id validado impede '/', '..' e afins."""
    validate_authority_id(authority_id)
    return Path(private_dir) / f"authority_{authority_id}.key"


# ------------------------------------------------------------------- autoridade
class Authority:
    """Uma autoridade eleitoral e sua parcela ``x_i`` da chave privada.

    Instâncias devem existir apenas no processo da própria autoridade.
    ``x_i`` nunca aparece em ``repr``/``str`` nem em ``public_key()``.

    Não confundir com ``src.server.registration.Authority``, que guarda só os
    dados públicos cadastrados; importe-a com alias (``RegisteredAuthority``).
    """

    __slots__ = ("authority_id", "group", "_x", "_h")

    def __init__(self, authority_id: str, group: GroupParams, x: int) -> None:
        validate_authority_id(authority_id)
        _check_group(group)
        if type(x) is not int or not 2 <= x <= group.q - 1:
            raise ValueError("chave privada fora do intervalo [2, q-1]")
        self.authority_id = authority_id
        self.group = group
        self._x = x
        self._h = mod_exp(group.g, x, group.p)

    @classmethod
    def generate(
        cls,
        authority_id: str,
        group: GroupParams,
        private_dir: Path | str = DEFAULT_PRIVATE_DIR,
        *,
        overwrite: bool = False,
    ) -> "Authority":
        """Gera ``x_i`` aleatório seguro em ``[2, q-1]`` e salva no arquivo privado."""
        _check_group(group)
        # secrets.randbelow(n) devolve [0, n-1]; deslocado fica em [2, q-1].
        x = 2 + secrets.randbelow(group.q - 2)
        authority = cls(authority_id, group, x)
        authority.save(private_dir, overwrite=overwrite)
        return authority

    def save(self, private_dir: Path | str = DEFAULT_PRIVATE_DIR, *, overwrite: bool = False) -> Path:
        """Grava a chave privada em JSON, com permissão 0600 quando o SO permite."""
        path = key_path(self.authority_id, private_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": KEY_FILE_VERSION,
            "authority_id": self.authority_id,
            "group": _group_dict(self.group),
            "x": self._x,
            "h": self._h,
        }
        flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            raise FileExistsError(
                f"{path} já existe; use overwrite=True para substituir a chave"
            ) from None
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
        return path

    @classmethod
    def load(
        cls,
        authority_id: str,
        group: GroupParams,
        private_dir: Path | str = DEFAULT_PRIVATE_DIR,
    ) -> "Authority":
        """Carrega a chave da autoridade e confere id, grupo e ``h_i`` gravados."""
        path = key_path(authority_id, private_dir)
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if data.get("authority_id") != authority_id:
            raise ValueError(f"{path} pertence a outra autoridade")
        if data.get("group") != _group_dict(group):
            raise ValueError(f"{path} foi gerado com outros parâmetros de grupo")
        authority = cls(authority_id, group, data["x"])
        if authority._h != data.get("h"):
            raise ValueError(f"{path} está corrompido: h não corresponde a x")
        return authority

    def public_key(self) -> AuthorityPublicKey:
        return AuthorityPublicKey(self.authority_id, self._h)

    def __repr__(self) -> str:  # nunca expõe x_i
        return f"Authority(id={self.authority_id!r}, h={self._h})"

    __str__ = __repr__


def generate_authorities(
    n: int,
    group: GroupParams,
    private_dir: Path | str = DEFAULT_PRIVATE_DIR,
    *,
    overwrite: bool = False,
) -> list[AuthorityPublicKey]:
    """Gera ``n`` autoridades com ids ``"1"``..``str(n)`` e devolve SÓ as chaves públicas.

    Exige ``n >= MIN_AUTHORITIES``. Os arquivos ficam em ``authority_1.key``,
    ``authority_2.key``… Cada ``Authority`` é descartada após salvar sua
    chave, então o chamador (CLI/servidor) nunca recebe ``x_i``.
    """
    if type(n) is not int or n < MIN_AUTHORITIES:
        raise ValueError(f"a eleição exige pelo menos {MIN_AUTHORITIES} autoridades")
    return [
        Authority.generate(str(i), group, private_dir, overwrite=overwrite).public_key()
        for i in range(1, n + 1)
    ]


# -------------------------------------------------------- chave pública conjunta
def _parse_public_key(value: object, authority_id: object) -> int:
    # O cadastro exporta h_i como string decimal; aceitamos apenas esse formato.
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        raise JointKeyError(f"public_key da autoridade {authority_id!r} não é decimal")
    return int(value)


def _check_min_authorities(min_authorities: int) -> None:
    if type(min_authorities) is not int or min_authorities < 1:
        raise ValueError("min_authorities deve ser um inteiro >= 1")


def compute_joint_public_key(
    public_data: dict,
    group: GroupParams,
    *,
    min_authorities: int = MIN_AUTHORITIES,
) -> int:
    """Calcula ``h = Π h_i mod p`` a partir de ``Registration.export_public_data()``.

    Exige pelo menos ``min_authorities`` autoridades (padrão: 3). Usa somente
    as chaves públicas exportadas; ``Σ x_i`` nunca é calculado.
    """
    _check_group(group)
    _check_min_authorities(min_authorities)
    authorities = public_data.get("authorities") if isinstance(public_data, dict) else None
    if not isinstance(authorities, list):
        raise JointKeyError("dados públicos sem a lista de autoridades")
    if len(authorities) < min_authorities:
        raise JointKeyError(
            f"a chave conjunta exige pelo menos {min_authorities} autoridades; "
            f"há {len(authorities)} cadastrada(s)"
        )

    seen: set[str] = set()
    h = 1
    for entry in authorities:
        authority_id = entry.get("authority_id") if isinstance(entry, dict) else None
        if authority_id in seen:
            raise JointKeyError(f"autoridade {authority_id!r} repetida nos dados públicos")
        seen.add(authority_id)
        h_i = _parse_public_key(entry.get("public_key"), authority_id)
        if not 1 < h_i < group.p:
            raise JointKeyError(f"public_key da autoridade {authority_id!r} fora de (1, p)")
        h = (h * h_i) % group.p
    return h


def publish_joint_public_key(
    public_data: dict,
    group: GroupParams,
    election_path: Path | str = DEFAULT_ELECTION_PATH,
    *,
    min_authorities: int = MIN_AUTHORITIES,
) -> dict:
    """Publica dados do cadastro, grupo e ``h`` em ``election.json``.

    Se houver menos de ``min_authorities`` autoridades, lança ``JointKeyError``
    sem criar nem alterar o arquivo.

    Ordem de precedência ao mesclar: campos já existentes no arquivo (ex.:
    candidatos) < campos de ``export_public_data()`` < ``group`` e
    ``joint_public_key``. Inteiros grandes são gravados como strings decimais,
    no mesmo padrão do cadastro. O dicionário recebido não é modificado.
    """
    joint_key = compute_joint_public_key(public_data, group, min_authorities=min_authorities)

    path = Path(election_path)
    election: dict = {}
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            election = json.load(fh)
    election.update(copy.deepcopy(public_data))
    election["group"] = {k: str(v) for k, v in _group_dict(group).items()}
    election["joint_public_key"] = str(joint_key)

    _atomic_write_json(path, election)
    return election


def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
