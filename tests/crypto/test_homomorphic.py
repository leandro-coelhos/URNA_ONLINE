from src.crypto.elgamal import bounded_discrete_log, derive_public_key, encrypt_bit
from src.crypto.group import GroupParameters
from src.crypto.homomorphic import (
    aggregate_ciphertexts,
    decrypt_aggregate_with_partials,
)


def test_homomorphic_sum_with_one_authority():
    parameters = GroupParameters(p=23, q=11, g=2, name="test-group")
    private_key = 7
    public_key = derive_public_key(private_key, parameters)
    first, _ = encrypt_bit(1, public_key, parameters, randomness=2)
    second, _ = encrypt_bit(0, public_key, parameters, randomness=3)
    third, _ = encrypt_bit(1, public_key, parameters, randomness=4)

    aggregate = aggregate_ciphertexts([first, second, third], parameters)
    partial = pow(aggregate.a, private_key, parameters.p)
    group_element = decrypt_aggregate_with_partials(aggregate, [partial], parameters)

    assert bounded_discrete_log(group_element, parameters, maximum=3) == 2


