"""Publicação somente por acréscimo em JSONL (issue #8 / T08).

O servidor chama append após suas validações eleitorais. Aqui repetimos as
verificações de assinatura, elegibilidade e unicidade como defesa local. Cada
sucesso significa que a linha foi escrita, flush e fsync concluíram. A classe
não controla estados eleitorais nem emite o recibo da issue #6.

Usa flock, disponível em Linux/WSL e outros Unix. O bloqueio coordena escritores
que seguem este protocolo; não impede adulteração por um administrador.
"""

from collections.abc import Mapping, Sequence
from copy import deepcopy
import fcntl
import os
from pathlib import Path
from typing import BinaryIO

from src.bulletin_board.hash_chain import (
    DuplicateVoteError, encode_record, genesis_hash, make_checkpoint, make_record,
    read_records, validate_public_context, verify_board,
)
from src.crypto.ballots import verify_signed_ballot


class BulletinBoard:
    """Quadro existente, aberto apenas após conferir um checkpoint confiável.

    Use create para iniciar um arquivo novo. Para retomar depois de reiniciar
    o processo, informe o último checkpoint preservado independentemente.
    """

    def __init__(
        self, path: str | Path, *, election_id: str, candidate_ids: Sequence[str],
        voter_public_keys: Mapping[str, str | bytes], expected_checkpoint: dict,
    ):
        self._path = Path(path)
        self._context = validate_public_context(
            election_id=election_id, candidate_ids=candidate_ids, voter_public_keys=voter_public_keys
        )
        self._checkpoint = deepcopy(expected_checkpoint)
        # Nunca recria silenciosamente um arquivo perdido/adulterado.
        self.records()

    @classmethod
    def create(
        cls, path: str | Path, *, election_id: str, candidate_ids: Sequence[str],
        voter_public_keys: Mapping[str, str | bytes],
    ) -> "BulletinBoard":
        """Cria um quadro vazio, sem sobrescrever um caminho já existente."""
        context = validate_public_context(
            election_id=election_id, candidate_ids=candidate_ids, voter_public_keys=voter_public_keys
        )
        checkpoint = make_checkpoint(election_id=election_id, size=0, head_hash=genesis_hash(election_id))
        # xb = criação exclusiva binária. A pasta deve existir previamente.
        with Path(path).open("xb") as stream:
            stream.flush()
            os.fsync(stream.fileno())
        return cls(path, **context, expected_checkpoint=checkpoint)

    @property
    def checkpoint(self) -> dict:
        """Cópia do último resumo aceito por esta instância; não é um recibo."""
        return deepcopy(self._checkpoint)

    def _read_verified(self, stream: BinaryIO) -> list[dict]:
        # Materializa durante a verificação: entradas inválidas interrompem a
        # leitura, e elegibilidade/unicidade limitam os registros ao cadastro.
        collected = []

        def collect():
            for record in read_records(stream):
                collected.append(record)
                yield record

        verify_board(collect(), **self._context, expected_checkpoint=self._checkpoint)
        return collected

    def records(self) -> list[dict]:
        """Relê e verifica o arquivo; editar o retorno não altera o quadro."""
        with self._path.open("rb") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
            return self._read_verified(stream)
        # Fechar o arquivo libera o bloqueio, inclusive ao ocorrer uma exceção.

    def append(self, envelope: dict) -> dict:
        """Autentica e grava uma cédula, devolvendo seu registro público.

        Uma instância com checkpoint desatualizado falha, em vez de adotar
        alterações externas automaticamente. Em erro de I/O, não há sucesso
        nem atualização do checkpoint; o operador precisa conferir o arquivo.
        """
        # r+b não cria nem trunca. O bloqueio engloba leitura, validação e escrita.
        with self._path.open("r+b") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            records = self._read_verified(stream)
            record = make_record(
                envelope, index=len(records), previous_hash=self._checkpoint["head_hash"]
            )
            ballot = verify_signed_ballot(
                {"ballot": record["ballot"], "signature": record["signature"]}, **self._context
            )
            if any(r["ballot"]["voter_id"] == ballot["voter_id"] for r in records):
                raise DuplicateVoteError("Este eleitor já possui uma cédula no quadro.")
            line = encode_record(record)
            stream.seek(0, os.SEEK_END)
            if stream.write(line) != len(line):
                raise OSError("Gravação incompleta do registro público.")
            stream.flush()
            os.fsync(stream.fileno())
            # Só avança depois de a escrita ter sido sincronizada com o disco.
            self._checkpoint = make_checkpoint(
                election_id=self._context["election_id"], size=len(records) + 1, head_hash=record["hash"]
            )
            return deepcopy(record)
