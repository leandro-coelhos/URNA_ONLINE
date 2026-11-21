import pytest

from src.crypto.elgamal import (
    Ciphertext,
    bounded_discrete_log,
    decrypt_to_group_element,
    derive_public_key,
    encrypt_bit,
)
from src.crypto.group import GroupParameters


@pytest.fixture
def small_parameters():
    # Grupo pequeno apenas para os testes rápidos; nunca usar em produção.
    p = 23
    return GroupParameters(p=p, q=11, g=2, name="test-group")


def test_encrypt_and_decrypt_bit(small_parameters):
    private_key = 7
    public_key = derive_public_key(private_key, small_parameters)
    ciphertext, _ = encrypt_bit(1, public_key, small_parameters, randomness=3)
    group_element = decrypt_to_group_element(ciphertext, private_key, small_parameters)
    assert bounded_discrete_log(group_element, small_parameters, maximum=1) == 1


def test_same_message_with_different_randomness_has_different_ciphertext(small_parameters):
    public_key = derive_public_key(7, small_parameters)
    first, _ = encrypt_bit(0, public_key, small_parameters, randomness=2)
    second, _ = encrypt_bit(0, public_key, small_parameters, randomness=3)
    assert first != second


def test_encrypt_rejects_non_bit(small_parameters):
    public_key = derive_public_key(7, small_parameters)
    with pytest.raises(ValueError):
        encrypt_bit(2, public_key, small_parameters)


def test_bounded_discrete_log_rejects_missing_value(small_parameters):
    public_key = derive_public_key(7, small_parameters)
    ciphertext, _ = encrypt_bit(1, public_key, small_parameters, randomness=3)
    group_element = decrypt_to_group_element(ciphertext, 7, small_parameters)
    with pytest.raises(ValueError):
        bounded_discrete_log(group_element, small_parameters, maximum=0)


