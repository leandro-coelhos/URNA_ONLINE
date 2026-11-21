from src.crypto.bit_proof import prove_bit, verify_bit_proof
from src.crypto.elgamal import derive_public_key, encrypt_bit
from src.crypto.group import GroupParameters


def test_bit_proof_accepts_zero_and_one():
    parameters = GroupParameters(p=23, q=11, g=2, name="test-group")
    private_key = 7
    public_key = derive_public_key(private_key, parameters)

    for message, randomness in ((0, 3), (1, 4)):
        ciphertext, returned_randomness = encrypt_bit(
            message, public_key, parameters, randomness=randomness
        )
        proof = prove_bit(
            ciphertext,
            public_key,
            returned_randomness,
            message,
            parameters,
            context=b"candidate-a",
        )
        assert verify_bit_proof(
            ciphertext,
            public_key,
            proof,
            parameters,
            context=b"candidate-a",
        )


def test_bit_proof_rejects_changed_ciphertext():
    parameters = GroupParameters(p=23, q=11, g=2, name="test-group")
    public_key = derive_public_key(7, parameters)
    ciphertext, randomness = encrypt_bit(1, public_key, parameters, randomness=4)
    proof = prove_bit(ciphertext, public_key, randomness, 1, parameters)
    changed_ciphertext = type(ciphertext)(ciphertext.a, (ciphertext.b + 1) % parameters.p)

    assert not verify_bit_proof(changed_ciphertext, public_key, proof, parameters)


