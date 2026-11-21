# Módulo de parâmetros e operações do grupo

Este módulo concentra os valores públicos e as operações matemáticas usadas pela criptografia da urna. Ele usa o grupo MODP 14 do RFC 3526: um primo `p` de 2048 bits, o subgrupo de ordem `q = (p - 1) / 2` e o gerador `g = 2`.

## Como funciona

- `parameters.py` define `GroupParameters` e disponibiliza `DEFAULT_PARAMETERS`.
- `operations.py` valida os parâmetros, sorteia escalares com `secrets`, calcula inversos modulares e verifica se um valor pertence ao subgrupo.
- A validação é feita no início do uso para evitar que uma configuração inválida seja utilizada silenciosamente.

## Entradas e saídas principais

### `GroupParameters`

Entrada: `p`, `q`, `g` e um nome opcional.

Saída: objeto imutável com os parâmetros públicos do grupo.

### `validate_parameters(parameters)`

Entrada: um `GroupParameters`.

Saída: `None` quando a configuração é válida; lança `ValueError` quando há inconsistência.

### `inverse_mod(value, modulus)`

Entrada: um valor e o módulo.

Saída: o inverso multiplicativo, isto é, o número `x` que satisfaz `(value * x) mod modulus = 1`.

### `random_scalar(order)`

Entrada: a ordem do subgrupo.

Saída: um escalar aleatório no intervalo `[1, order - 1]`.

## Exemplo

```python
from src.crypto.group import DEFAULT_PARAMETERS, validate_parameters

validate_parameters(DEFAULT_PARAMETERS)
print(DEFAULT_PARAMETERS.p.bit_length())  # 2048
```

## Cuidados

`p`, `q` e `g` são públicos. Chaves privadas, fatores aleatórios e qualquer segredo de autoridade não devem ser colocados neste módulo nem enviados ao repositório.


