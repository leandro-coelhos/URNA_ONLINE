from src.crypto.group import (
    DEFAULT_PARAMETERS,
    GroupParameters,
    inverse_mod,
    is_group_element,
    random_scalar,
    validate_parameters,
)


def test_default_parameters_have_expected_structure():
    validate_parameters(DEFAULT_PARAMETERS)
    assert DEFAULT_PARAMETERS.p.bit_length() >= 2048
    assert DEFAULT_PARAMETERS.g == 2
    assert (DEFAULT_PARAMETERS.p - 1) % DEFAULT_PARAMETERS.q == 0


def test_inverse_modular():
    assert (17 * inverse_mod(17, 101)) % 101 == 1


def test_random_scalar_is_inside_subgroup_order():
    value = random_scalar(DEFAULT_PARAMETERS.q)
    assert 1 <= value < DEFAULT_PARAMETERS.q


def test_group_element_validation():
    element = pow(DEFAULT_PARAMETERS.g, 123, DEFAULT_PARAMETERS.p)
    assert is_group_element(element, DEFAULT_PARAMETERS)
    assert not is_group_element(0, DEFAULT_PARAMETERS)


def test_small_invalid_parameters_are_rejected():
    invalid = GroupParameters(p=23, q=11, g=2)
    try:
        validate_parameters(invalid)
    except ValueError:
        pass
    else:
        raise AssertionError("parâmetros pequenos deveriam ser rejeitados")


