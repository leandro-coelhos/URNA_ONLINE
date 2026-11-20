# Módulo de prova de que o voto é um bit

Este módulo implementa uma prova OR de Chaum-Pedersen, transformada em prova não interativa pelo desafio Fiat-Shamir. O eleitor demonstra que a cifra contém `0` ou `1` sem revelar qual dos dois valores foi escolhido.

## Ideia da prova

Para uma cifra `(a, b)`, com `a = g^r`, existem duas afirmações possíveis:

```text
m = 0: b     = h^r
m = 1: b / g = h^r
```

O provador conhece a aleatoriedade `r` de apenas uma das afirmações. Para a outra, ele simula uma resposta. O verificador confere as duas ramificações e a soma dos desafios, mas não consegue identificar qual ramificação foi a verdadeira.

## Entradas e saídas principais

### `prove_bit(ciphertext, public_key, randomness, message, context=b"")`

Entradas:

- `ciphertext`: cifra ElGamal;
- `public_key`: chave pública;
- `randomness`: o mesmo `r` usado em `encrypt_bit`;
- `message`: `0` ou `1`;
- `context`: bytes opcionais para separar eleições ou transcripts.

Saída: um objeto `BitProof` com compromissos, desafios e respostas das duas ramificações.

### `verify_bit_proof(ciphertext, public_key, proof, context=b"")`

Entradas: a cifra, a chave pública, a prova e o mesmo contexto usado na criação.

Saída: `True` se a prova for consistente; `False` caso contrário.

## Fluxo esperado

1. O módulo ElGamal cifra o voto e retorna `ciphertext` e `randomness`.
2. O provador chama `prove_bit` e envia apenas a cifra e a prova.
3. O verificador chama `verify_bit_proof` antes de aceitar a cifra.
4. A aleatoriedade usada para provar o voto continua privada.

## Cuidados

O contexto deve ser igual nos dois lados. Em produção, a implementação deve ser revisada com o restante do protocolo, principalmente serialização, prevenção de replay e tratamento das chaves. Esta prova demonstra apenas que o plaintext pertence a `{0, 1}`; ela não autentica sozinha o eleitor.


