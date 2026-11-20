# Assinaturas digitais das cédulas — issue #7 (T06)

## Objetivo e componentes

A assinatura associa uma cédula cifrada à chave RSA cadastrada do eleitor e
permite detectar alterações. Ela não cifra o voto nem comprova que as cifras
representam uma escolha permitida. O eleitor assina depois de cifrar os votos.

| Arquivo | Responsabilidade |
|---|---|
| `src/crypto/keys.py` | Política RSA pública compartilhada com a #4 |
| `src/crypto/signatures.py` | Geração de chave no eleitor, assinatura e verificação de bytes |
| `src/crypto/ballots.py` | Esquema da cédula, serialização canônica, envelope e autenticação |
| `tests/test_signatures.py` | Testes positivos, ataques e integração com a exportação da #4 |

Esses módulos criptográficos não importam `src.server`. O auditor pode utilizá-los
com os dados públicos, mantendo a separação prevista no README. A verificação
está disponível para o servidor, mas o ciclo completo de recebimento de votos
da #5 ainda não foi integrado.

## Parâmetros e justificativas

- Assinatura: **RSA-PSS**, com **SHA-256** e **MGF1/SHA-256**.
- Salt PSS: **32 bytes**. Os parâmetros são fixos, não escolhidos pelo remetente.
- Chaves geradas por `generate_signing_key`: 3072 bits por padrão, expoente 65537.
  A geração também admite 2048, 4096 e 8192 bits; os testes usam principalmente
  2048 por desempenho. A política de verificação permanece compatível com a #4.
- Biblioteca: `cryptography==49.0.0`, permitida para operações RSA pelo enunciado.
- Assinatura no envelope: Base64 padrão com padding, em representação canônica.

PSS é o esquema recomendado pela documentação da biblioteca para novos protocolos.
O tamanho padrão de 3072 bits é uma escolha conservadora dentro da política do
cadastro. A segurança do sistema também depende do grupo ElGamal, da geração
aleatória e do restante do protocolo, não apenas do tamanho RSA.

O salt torna a assinatura probabilística: assinar duas vezes a mesma mensagem
pode produzir assinaturas diferentes, ambas válidas. Isso NÃO permite dois votos;
a unicidade precisa ser aplicada por identificador de eleitor na #5.

## Formato público proposto — versão 1

Exemplo didático com componentes pequenos, sem afirmar validade ElGamal:

```json
{
  "schema_version": 1,
  "election_id": "eleicao_2026",
  "voter_id": "eleitor_001",
  "ciphertexts": [
    {"candidate_id": "A", "c1": "4", "c2": "8"},
    {"candidate_id": "B", "c1": "16", "c2": "32"}
  ]
}
```

`ciphertexts` segue exatamente a ordem dos candidatos da configuração pública.
Cada entrada representa uma cifra `(c1, c2)` do ElGamal exponencial. Componentes
são strings decimais positivas, sem sinal, espaços ou zeros à esquerda, para
preservar inteiros grandes em implementações que leem JSON. O produtor das cifras
deve convertê-las com `str` antes de montar a cédula.

Identificadores seguem a mesma regra da #4: ASCII, 1 a 64 caracteres, começando
por letra ou algarismo, com `_` e `-` permitidos no restante. Não há nomes livres
ou Unicode nos campos assinados desta versão. Nomes exibidos dos candidatos ficam
na configuração; são seus identificadores que aparecem na cédula.

Há de 2 a 128 candidatos e até 2500 algarismos em cada componente. São limites
de implementação para controlar o processamento. O limite de componentes comporta
grupos de até 8192 bits; não substitui verificar seus valores contra p e q.
O leitor de envelopes limita o documento a 1 MiB, suficiente para a maior cédula
admitida. O futuro leitor de rede/disco também deve limitar a entrada antes de
carregá-la inteira na memória.

O esquema exige exatamente os campos definidos. Não aceita escolha em claro,
aleatoriedade `r`, timestamps, chave pública do remetente ou campos desconhecidos.
Não há provas de bit nesta versão. A #12 deverá estender o esquema, documentar
a versão e incluir integralmente as provas na mensagem assinada, sem descartá-las
ou excluí-las silenciosamente da assinatura.

## Bytes exatos assinados

`canonical_ballot_bytes` valida o esquema e serializa com:

```python
json.dumps(
    ballot,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
    allow_nan=False,
).encode("ascii")
```

As chaves dos objetos são ordenadas e não há espaços extras. A ordem das listas
é preservada. Alterar a apresentação do JSON (indentação ou ordem dos campos de
um objeto) não altera o significado; reordenar candidatos altera a mensagem.

Não se trata de uma implementação genérica de JSON Canonicalization Scheme
(RFC 8785). É uma regra própria para um esquema restrito a ASCII, strings decimais,
listas e a versão inteira 1, com bytes de referência conferidos por teste.

Antes de assinar, acrescentamos o prefixo fixo:

```python
b"URNA_ONLINE:BALLOT:v1\x00" + canonical_ballot_bytes(ballot)
```

O byte final `\x00` separa o domínio do conteúdo. Esse prefixo identifica o
propósito da assinatura; recibos e outros documentos deverão usar domínios
diferentes. A biblioteca aplica SHA-256 e PSS a esses bytes; não pré-calculamos
um segundo hash. O prefixo não é um campo alterável do envelope.

O envelope devolvido por `sign_ballot` contém exatamente `ballot` e `signature`:

```text
{
  "ballot": <cédula completa no esquema acima>,
  "signature": <assinatura RSA codificada em Base64>
}
```

Ele não inclui chave privada, chave pública nem identificador de algoritmo
selecionável pelo remetente. A mensagem contém a identificação do eleitor:
o sigilo da escolha depende da cifragem, não do anonimato da identidade no quadro.

## API e fluxo de integração

| Função | Uso |
|---|---|
| `generate_signing_key(key_size=3072)` | No eleitor: gera e devolve um objeto de chave privada, sem gravá-lo |
| `public_key_to_pem(private_key.public_key())` | Obtém a chave pública para registrar na #4 |
| `sign_bytes(data, private_key)` | Assina bytes com RSA-PSS/SHA-256 |
| `verify_bytes(data, signature, public_key_pem)` | Devolve True/False para a assinatura; chave/tipos inválidos geram exceção |
| `canonical_ballot_bytes(ballot)` | Confere o esquema e devolve JSON canônico em bytes |
| `sign_ballot(ballot, private_key)` | No eleitor: devolve uma cópia da cédula e assinatura Base64 |
| `load_signed_ballot(document)` | Lê JSON e confere formato, mas NÃO verifica assinatura |
| `verify_signed_ballot(envelope, ...)` | Confere contexto, elegibilidade e assinatura; devolve cópia da cédula ou lança erro |

Antes de cadastrar, o eleitor gera seu par RSA. Ele envia somente a parte pública.
Depois de cifrar, usa a chave privada local para assinar a cédula.
Não há escrita ou leitura de chaves privadas em disco nesta entrega. Essa gestão
precisa ser definida na CLI/persistência; nunca deve transferir os segredos ao servidor.

Exemplo de verificação, com variáveis fornecidas pelos módulos da eleição:

```python
from src.crypto.ballots import load_signed_ballot, verify_signed_ballot

# A origem destes dados públicos precisa ser autenticada pelo protocolo.
public_data = cadastro.export_public_data()
voter_keys = {
    voter["voter_id"]: voter["public_key_pem"]
    for voter in public_data["voters"]
}
envelope = load_signed_ballot(documento_recebido)
ballot = verify_signed_ballot(
    envelope,
    election_id=public_data["election_id"],
    candidate_ids=["A", "B"],  # Obter da configuração pública real.
    voter_public_keys=voter_keys,
)
# O controlador ainda verifica etapa, voto anterior e validade criptográfica.
# Só depois dessas verificações a cédula pode ser aceita no quadro público.
```

O auditor pode construir `voter_keys` a partir do arquivo público autenticado,
sem receber o objeto `cadastro`. `verify_signed_ballot` não o acessa internamente.
Se o contexto recebido foi adulterado (por exemplo, chave de eleitor substituída),
a assinatura sozinha não identifica essa substituição.

Use `load_signed_ballot` para documentos externos. Ele rejeita campos JSON
duplicados em qualquer nível, codificação inválida, NaN/Infinity e envelopes
fora do esquema. Um `json.loads` comum pode descartar campos repetidos antes que
o verificador os veja; não é um substituto equivalente para essa fronteira.

## Erros e comportamento de rejeição

- `BallotFormatError`: formato ou versão inválidos, campos extras, componentes
  não canônicos, Base64 inválido ou candidatos repetidos.
- `IneligibleVoterError`: eleitor ausente do cadastro público fornecido.
- `InvalidBallotSignatureError`: assinatura alterada, cédula alterada ou chave errada.
- `BallotError`: contexto de outra eleição ou candidatos/ordem diferentes.
- `PublicKeyError`: chave pública de verificação inválida. É uma falha do cadastro
  fornecido e também impede autenticar a cédula; não deve ser ignorada pelo chamador.

Assinador e verificador devolvem cópias independentes, evitando que uma edição
posterior da entrada altere os dados retornados por referência.

## Critérios da #7 e testes

| Critério | Evidências |
|---|---|
| Assinatura válida aceita | Ciclo de assinatura/verificação e interoperabilidade direta com a biblioteca |
| Alteração da cédula invalida a assinatura | Mudança de c1/c2, eleitor, eleição, candidato e ordem |
| Eleitor não cadastrado rejeitado | Verificação de cadastro vazio mesmo com assinatura matematicamente válida |
| Serialização assinada documentada | Regra e prefixo acima; teste com bytes canônicos esperados |

Também há testes para assinatura por outra chave, reuso entre eleições, domínio
de recibo, tentativa de alterar algoritmo/salt, campos JSON duplicados, entradas
inválidas e limites de tamanho. A integração real com a exportação pública da #4
é testada; isso não equivale à integração do ciclo completo da eleição.

```bash
python3 -m unittest tests.test_signatures -v
python3 -m unittest discover -s tests -v
```

## Limitações que devem constar da análise de segurança

- Assinatura válida não prova mensagem 0/1, soma igual a 1, pertencimento ao grupo
  nem correção das provas. Eleitores maliciosos também podem assinar mensagens.
- Reenvio na MESMA eleição pode ter assinatura válida: a #5 deve impedir voto
  duplicado e verificar o período de votação. Não mantenha esse estado no módulo
  criptográfico usado pelo auditor.
- `election_id` protege contra reuso entre identificadores diferentes. A configuração
  e o cadastro devem estar fixados/autenticados; não se deve reutilizar o mesmo
  identificador para eleições diferentes ou mudar candidatos/chaves após a abertura.
- Não há prova de identidade civil nem proteção de uma chave privada comprometida.
- Não há garantia de receipt-freeness/coerção. A assinatura da cifra e a ausência
  de `r` no envelope não resolvem a possibilidade de o eleitor guardar e revelar
  a aleatoriedade que usou; o relatório deve analisar esse caso.
- Os pares pequenos usados nos testes são sintéticos. Não são uma demonstração
  de ElGamal seguro, apuração ou validade da eleição completa.

## Referências

- [RSA, PSS e verificação — cryptography 49.0.0](https://cryptography.io/en/49.0.0/hazmat/primitives/asymmetric/rsa/).
- [Serialização JSON — biblioteca padrão do Python](https://docs.python.org/3/library/json.html).
