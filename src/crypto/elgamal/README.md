# Módulo ElGamal

Este módulo implementa a cifra ElGamal no formato exponencial para mensagens binárias. Em vez de cifrar diretamente o número `m`, a mensagem é representada como `g^m`.

Para uma chave pública `h = g^x` e uma aleatoriedade `r`, a cifra é:

```text
a = g^r
b = g^m * h^r
```

Assim, a cifra contém o par `(a, b)` e não expõe o voto individual.

## Entradas e saídas principais

### `derive_public_key(private_key)`

Entrada: chave privada `x`, no intervalo `[1, q - 1]`.

Saída: chave pública `h = g^x mod p`.

### `encrypt_bit(message, public_key, randomness=None)`

Entradas:

- `message`: somente `0` ou `1`;
- `public_key`: chave pública da eleição;
- `randomness`: opcional e usado apenas para testes ou para produzir a prova de bit.

Saída: tupla `(Ciphertext, r)`, contendo a cifra e o fator aleatório. O `r` deve permanecer secreto, pois será usado para produzir a prova e não pode aparecer no recibo.

### `decrypt_to_group_element(ciphertext, private_key)`

Entradas: uma cifra e uma chave privada.

Saída: `g^m`, e não o número `m` diretamente. Na apuração, o resultado segue para `bounded_discrete_log`.

### `bounded_discrete_log(group_element, maximum)`

Entradas: `g^m` e o maior total de votos possível.

Saída: `m`, encontrado por busca limitada. Como o total da eleição é pequeno, não é necessário resolver um logaritmo discreto geral.

## Exemplo conceitual

```python
from src.crypto.elgamal import derive_public_key, encrypt_bit

public_key = derive_public_key(private_key)
ciphertext, randomness = encrypt_bit(1, public_key)
```

O servidor pode armazenar `ciphertext`, mas `private_key` e `randomness` continuam protegidos.

## Cuidados

Nunca reutilize a mesma aleatoriedade em duas cifras. Este módulo aceita `randomness` explicitamente para que a Pessoa 1 consiga gerar a prova de bit; em uma execução real, o valor deve ser sorteado pelo módulo `secrets`.


