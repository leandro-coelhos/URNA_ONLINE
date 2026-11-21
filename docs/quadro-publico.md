# Quadro público — issue #8 / T08

## Entrega e posição na arquitetura

A #8 implementa o quadro público em `src/bulletin_board/`, conforme a divisão
do README. A #4 fornece o cadastro público; a #7 fornece cédulas assinadas;
esta etapa publica essas cédulas e verifica o histórico. O README não foi alterado.

- `hash_chain.py`: formato, SHA-256, leitura JSONL e verificação com dados públicos.
- `board.py`: criação, reabertura, consulta e acréscimo ao arquivo público.
- `tests/test_bulletin_board.py`: 36 testes, incluindo ataques ao histórico.

Agora há **persistência do quadro em JSONL**. Ela é explícita: o programa que
usar `BulletinBoard.create(caminho, ...)` escolhe um arquivo e uma pasta existente.
Importar o módulo não cria arquivos. Os testes usam diretórios temporários;
não foi criada uma eleição em `data/`. A persistência do cadastro da #4 continua
fora desta implementação.

## Contrato público versão 1

O arquivo sugerido pelo README é `data/public/bulletin_board.jsonl`. Cada linha
contém um objeto JSON completo, terminado por LF (`\n`). Não há cabeçalho;
um quadro vazio é um arquivo com zero bytes. O primeiro índice é **0**.

| Campo do registro | Tipo e significado |
|---|---|
| `schema_version` | Inteiro `1`; booleanos não são versões |
| `index` | Inteiro de 0 a `2**63 - 1`, consecutivo dentro do quadro |
| `previous_hash` | Hash do registro anterior; no índice 0, hash inicial |
| `ballot` | Cédula completa da #7, com eleição, eleitor e cifras |
| `signature` | Assinatura RSA-PSS do eleitor em Base64 canônico, conforme #7 |
| `hash` | SHA-256 do corpo canônico do registro, em hexadecimal minúsculo |

O eleitor está em `ballot.voter_id` e as cifras em `ballot.ciphertexts`.
Não repetimos esses dados no nível externo para evitar versões contraditórias.
O corpo do registro contém os outros cinco campos, sem o próprio `hash`.
Campos extras ou ausentes são rejeitados, inclusive na cédula interna.

Exemplo **ilustrativo, não validável**: as palavras entre `<...>` substituem
hashes e uma assinatura reais. No arquivo, o objeto ocuparia uma única linha.

```json
{
  "schema_version": 1,
  "index": 0,
  "previous_hash": "<hash inicial: 64 caracteres hexadecimais>",
  "ballot": {
    "schema_version": 1,
    "election_id": "eleicao_2026",
    "voter_id": "eleitor_1",
    "ciphertexts": [
      {"candidate_id": "A", "c1": "4", "c2": "8"},
      {"candidate_id": "B", "c1": "16", "c2": "32"}
    ]
  },
  "signature": "<assinatura do eleitor em Base64>",
  "hash": "<hash deste registro: 64 caracteres hexadecimais>"
}
```

Os valores pequenos são sintéticos. Não representam uma demonstração de
ElGamal válido, de prova 0/1 ou de apuração.

## Hash inicial e encadeamento

Definições exatas (`||` significa concatenar bytes):

```text
G = SHA256(b"URNA_ONLINE:BOARD:GENESIS:v1\x00" || election_id em ASCII)
H_i = SHA256(b"URNA_ONLINE:BOARD:RECORD:v1\x00" || JSON_canônico(corpo_i))
previous_hash_0 = G
previous_hash_i = H_(i-1), para i > 0
```

Na implementação, `hexdigest()` representa cada saída como 64 caracteres
hexadecimais minúsculos. O byte zero nos prefixos separa o domínio do conteúdo.
O hash inicial é diferente para identificadores de eleição diferentes. Ele
vincula o início ao identificador, **não autentica a configuração inteira**.
Identificadores de eleição devem ser únicos e os dados públicos devem ter
origem confiável antes de começar a votação.

A representação canônica usa `json.dumps` com `sort_keys=True`,
`separators=(",", ":")`, `ensure_ascii=True` e `allow_nan=False`, codificada em
ASCII. A ordem das chaves de objetos não importa; a ordem das listas importa.
É um esquema restrito do projeto, não uma implementação geral de RFC 8785.

O hash cobre índice, elo anterior, cédula inteira e assinatura. O eleitor
continua assinando somente a cédula no domínio da #7: ele ainda não conhece
o índice e o hash anterior quando prepara o voto.

## Checkpoint e administrador malicioso

Um checkpoint é um resumo de um **retrato exato** do quadro:

```text
{
  "schema_version": 1,
  "election_id": "eleicao_2026",
  "size": quantidade de registros,
  "head_hash": hash do último registro, ou G quando vazio
}
```

`verify_board` exige `expected_checkpoint`. Compara a quantidade e o hash final
recalculados com esse resumo. O checkpoint precisa ter sido preservado por um
observador confiável fora do controle do administrador. Ele é público e não
contém chaves privadas. **Gerar um checkpoint não o autentica.**

Essa exigência é necessária: remover só o último registro deixa os demais
elos coerentes. Além disso, qualquer pessoa consegue recalcular hashes depois
de excluir ou reordenar cédulas legitimamente assinadas. A assinatura de um
eleitor não autentica a posição ou a presença dos demais votos.

O teste `test_untrusted_checkpoint_cannot_protect_history` mostra os dois lados:
o quadro modificado passa se receber também o resumo escolhido pelo atacante,
mas falha contra o checkpoint original preservado.

**Contrato a integrar pelo grupo:** definir quem observa, confere e preserva
os checkpoints, como sua autenticidade é comunicada ao auditor e qual retrato
final é o do encerramento. Guardar um JSON ao lado do quadro, sob controle do
mesmo administrador, não resolve isso. A assinatura exclusiva do servidor
também não impede o próprio administrador de apresentar históricos diferentes.
Observadores precisam comparar o que receberam. A necessidade dessa comparação
também aparece no [RFC 9162, seção 11.3](https://www.rfc-editor.org/rfc/rfc9162.html#section-11.3),
que trata de logs de certificados; aqui usamos cadeia linear, não seu protocolo
de árvores Merkle.

Esta entrega fornece o formato e exige a âncora na verificação. Não implementa
distribuição, assinaturas de testemunhas, consenso ou proteção automática do
armazenamento externo. Não se pode afirmar a garantia completa contra um
administrador malicioso enquanto esse contrato não estiver integrado.

Um checkpoint antigo não é prova de que recebemos o retrato final: ele protege
apenas o histórico que já foi observado. Esta API rejeita acréscimos contra
um checkpoint de tamanho menor, mesmo que sejam legítimos. Para verificar
outro retrato, forneça o checkpoint confiável correspondente.

## API de publicação

O contexto passado às funções tem três valores públicos:

```python
context = {
    "election_id": public_registration["election_id"],
    "candidate_ids": ["A", "B"],  # Ordem definida na configuração da eleição.
    "voter_public_keys": {
        voter["voter_id"]: voter["public_key_pem"]
        for voter in public_registration["voters"]
    },
}
```

O cadastro deve estar congelado e autenticado. A classe copia a configuração
e valida os identificadores, a lista de candidatos e as chaves RSA. O mesmo
PEM normalizado não pode representar dois eleitores. Não há acesso a chaves
privadas, nem importação do estado do servidor.

Uso, supondo `context` e `signed_envelope` preparados pelas outras etapas:

```python
from pathlib import Path
from src.bulletin_board.board import BulletinBoard

directory = Path("data/public")
directory.mkdir(parents=True, exist_ok=True)
board = BulletinBoard.create(directory / "bulletin_board.jsonl", **context)
record = board.append(signed_envelope)
checkpoint = board.checkpoint
records = board.records()
```

`create` usa `xb`: falha se já existir um arquivo. `append` usa `r+b`: abre um
arquivo existente sem truncá-lo, verifica todo o histórico, autentica a nova
cédula, rejeita eleitor repetido e escreve somente no final. A confirmação vem
depois de `flush()` e `os.fsync()`. A documentação do
[Python sobre fsync](https://docs.python.org/3/library/os.html#os.fsync)
explica a necessidade de esvaziar primeiro o buffer do objeto de arquivo.

O retorno de `append` é o registro público. Ele fornece índice e hash para a
futura emissão do recibo da #6; ainda **não é um recibo assinado**. O servidor
só deve informar aceitação após a gravação bem-sucedida e os demais passos do
protocolo integrado. Rejeições de assinatura, elegibilidade ou duplicidade
não acrescentam linhas nem avançam o checkpoint.

Reabrir, usando um checkpoint preservado independentemente:

```python
board = BulletinBoard(
    "data/public/bulletin_board.jsonl", **context,
    expected_checkpoint=trusted_checkpoint,
)
```

O construtor confere o arquivo antes de permitir uso. Arquivo ausente, cadeia
adulterada ou linha final incompleta causa erro. Não há limpeza, truncamento
ou reconstrução silenciosa. A unicidade é recuperada lendo as cédulas já
publicadas, portanto continua valendo após reiniciar o processo.

`records()` relê e verifica o arquivo; não retorna uma lista interna editável.
`checkpoint` devolve uma cópia. Não há métodos de edição ou remoção de votos.

## Uso pelo auditor independente

O programa auditor da #17 poderá importar apenas `hash_chain.py` e as funções
criptográficas compartilhadas. Não precisa instanciar o servidor nem o escritor:

```python
from src.bulletin_board.hash_chain import read_records, verify_board

with open("data/public/bulletin_board.jsonl", "rb") as stream:
    verified_checkpoint = verify_board(
        read_records(stream), **context, expected_checkpoint=trusted_checkpoint,
    )
```

`read_records` somente lê JSONL: limite de 1 MiB por linha incluindo LF,
UTF-8 válido, objeto na raiz, sem campos duplicados, NaN ou Infinity. Não ignora
linhas vazias nem um final sem LF. Não autentica sozinho o conteúdo.

`verify_board` verifica formato e hash de cada registro, índices consecutivos,
elos, eleição, candidatos e sua ordem, elegibilidade, assinatura, unicidade
e correspondência com o checkpoint esperado. Retorna o resumo verificado ou
lança uma exceção. Não imprime “eleição válida”: produto homomórfico, provas,
autoridades e resultado ainda pertencem às outras partes do auditor.

| Exceção | Significado |
|---|---|
| `BoardFormatError` | Esquema, JSONL, metadados ou contexto malformados |
| `ChainIntegrityError` | Hash, posição, elo ou checkpoint incompatível |
| `DuplicateVoteError` | Eleitor aparece mais de uma vez |
| `BallotError` e subclasses da #7 | Cédula malformada, contexto incorreto, eleitor ausente ou assinatura inválida |
| `PublicKeyError` | Chave do cadastro fornecido inválida |
| `OSError` e subclasses | Falha de arquivo, permissão, criação exclusiva ou sincronização |

## Limites operacionais e integrações

- **Plataforma:** o escritor usa `fcntl.flock`, disponível no Linux/WSL e em
  outros Unix. Windows nativo exige adaptar os bloqueios. `hash_chain.py`
  não depende de `fcntl` e pode verificar uma cópia pública separadamente.
- **Concorrência:** bloqueio exclusivo abrange leitura, validação e escrita;
  consultas usam bloqueio compartilhado. Uma instância desatualizada falha
  em vez de adotar alterações externas. `flock` coordena processos que o
  respeitam; não impede um administrador de editar ou substituir o arquivo.
- **Falha de disco:** uma exceção pode ocorrer depois de os bytes terem sido
  escritos. O checkpoint não avança e não há rollback automático. A operação
  não pode ser anunciada como sucesso; é necessário comparar arquivo,
  checkpoints e evidências antes de recuperar. Não há transação distribuída,
  recuperação automática de falhas ou garantia contra toda queda de energia
  — inclusive não sincronizamos a entrada do diretório na criação.
- **Custo:** cada inclusão relê e verifica o quadro completo. Para N votos,
  a sequência de inclusões tem custo quadrático no número de registros. É
  uma escolha de simplicidade para a demonstração acadêmica, não de escala.
- **Estados e cifras:** o controlador da #5 deve permitir inclusão somente
  na votação aberta. A validação de grupo, 0/1 e soma igual a 1 deve preceder
  `append`. As funções daqui não recebem segredo nem decifram votos.
- **Privacidade:** não adicionamos timestamps ou escolhas em claro. Índices
  revelam a ordem dos registros e os identificadores são públicos, como
  exige o enunciado. Isso não resolve metadados de rede ou geração insegura
  das cifras; o sigilo depende da integração criptográfica completa.
- **Publicação:** o arquivo e a API permitem leitura pública, mas não criam
  uma página web, endpoint, replicação ou canal autenticado de distribuição.

## Critérios da issue e evidências

| Critério #8 | Evidência e condição |
|---|---|
| Toda cédula aceita aparece no quadro | `append` retorna após escrever e sincronizar; teste de três cédulas e preservação dos bytes anteriores |
| Estado inicial definido | Índice 0, hash inicial com domínio e identificador de eleição; quadro vazio tem checkpoint de tamanho 0 |
| Alterações detectadas | Testes de mudança de cifras, assinatura, índice e elo; assinatura é verificada mesmo com hashes recalculados |
| Remoções, reordenações e inserções indevidas detectadas | Verificação de sequência, assinaturas e unicidade, mais checkpoint externo; testes incluem remoção final, cadeia recalculada e voto extra legitimamente assinado |
| Formato público documentado | Contrato versão 1 e exemplos deste documento |

O teste de inserção de voto legítimo significa “não pertence ao retrato
comprometido pelo checkpoint”; não permite descobrir sozinho se um eleitor
assinou por vontade própria ou se o servidor cumpriu todas as etapas.

## Execução dos testes

Na raiz do projeto, com as dependências de `requirements.txt` instaladas:

```bash
python3 -m unittest tests.test_bulletin_board -v
python3 -m unittest discover -s tests -v
```

Resultado desta entrega: **36 testes da #8; 95 no total**, em Python 3.13.2
com `cryptography` 49.0.0. Além dos ataques, há testes de reabertura, cópias
independentes, integração com o cadastro congelado, falha simulada de `fsync`
e compatibilidade da maior cédula da #7 com o limite do leitor JSONL.

Os testes de consistência não substituem o auditor independente completo.
O guia pessoal detalhado está em `estudos-locais/guia-completo-quadro-publico.md`,
pasta ignorada pelo Git; este documento é a referência compartilhada.
