"""Operações de apuração homomórfica."""

from .tally import (
    aggregate_ciphertexts,
    combine_partial_decryptions,
    decrypt_aggregate_with_partials,
)

__all__ = [
    "aggregate_ciphertexts",
    "combine_partial_decryptions",
    "decrypt_aggregate_with_partials",
]


