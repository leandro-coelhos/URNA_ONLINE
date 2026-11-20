# Módulo de apuração homomórfica

Este módulo soma votos sem decifrar cada voto individual. Para ElGamal exponencial, a multiplicação de cifras corresponde à soma das mensagens:

```text
Enc(m1) * Enc(m2) = Enc(m1 + m2)
```

Por isso, a urna pode agregar as cifras de uma opção e só depois realizar a apuração.

## Entradas e saídas principais

### `aggregate_ciphertexts(ciphertexts)`

Entrada: uma coleção de objetos `Ciphertext` produzidos com os mesmos parâmetros e a mesma chave pública.

Saída: uma única `Ciphertext` que representa a soma dos votos.

O módulo multiplica os componentes `a` e `b` separadamente, sempre reduzindo módulo `p`.

### `combine_partial_decryptions(partials)`

Entrada: parcelas `a^(x_i)` calculadas pelas autoridades.

Saída: o fator conjunto `a^(x_1 + ... + x_n)` usado para remover a proteção da cifra agregada.

### `decrypt_aggregate_with_partials(aggregate, partials)`

Entradas: cifra agregada e parcelas de todas as autoridades necessárias.

Saída: `g^total`, onde `total` é o número de votos da opção. A conversão de `g^total` para `total` fica em `bounded_discrete_log`.

## Fluxo esperado

1. Receber as cifras válidas.
2. Agregar as cifras da opção.
3. Obter as parcelas das autoridades.
4. Remover o fator conjunto.
5. Recuperar o total dentro de um limite conhecido.

## Cuidados

Esta etapa não substitui a validação da prova de que cada cifra representa um bit. A apuração deve agregar somente cifras que já passaram pela verificação do módulo `bit_proof`.


