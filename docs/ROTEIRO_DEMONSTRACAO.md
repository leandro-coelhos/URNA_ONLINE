# Roteiro da demonstração — URNA_ONLINE (T15 / Issue #18)

Este roteiro acompanha o `demo.py`, que executa as 9 etapas da demonstração com os módulos reais do projeto (sem mocks e sem reduzir parâmetros: grupo RFC 3526 de 2048 bits e RSA-PSS de 3072 bits). Todas as linhas citadas abaixo foram copiadas da saída real, salva em [`demo_output_exemplo.txt`](demo_output_exemplo.txt).

> **Os números mudam a cada execução.** Chaves, `r`, `x_i`, cifras, hashes e recibos são aleatórios (`secrets`/`os.urandom`). O que se repete sempre: o cenário (eleitor-1→Alice, eleitor-2→Bob, eleitor-3→Alice), as decisões de cada etapa, os erros esperados, os totais **Alice 2, Bob 1** e o hash inicial do quadro (`previous 1054a8bf1c9288b0…`), que só depende do identificador da eleição `demo-t15`.

## Sumário

1. [Pré-requisitos](#1-pré-requisitos)
2. [Comandos](#2-comandos)
3. [Cronograma de 10 minutos](#3-cronograma-de-10-minutos)
4. [As 9 etapas](#4-as-9-etapas)
5. [Perguntas prováveis da banca](#5-perguntas-prováveis-da-banca)
6. [Plano B para falhas ao vivo](#6-plano-b-para-falhas-ao-vivo)

---

## 1. Pré-requisitos

**Sistema operacional: Linux, macOS ou WSL.** O quadro público (`src/bulletin_board/board.py`) trava o arquivo com `fcntl.flock`, e o módulo `fcntl` não existe no Windows nativo. No Windows nativo, o `demo.py` confere isso antes de tocar no disco e termina com **código 3**, sem criar nenhum arquivo:

```text
ERRO: o quadro público (src/bulletin_board/board.py) usa fcntl para travar o arquivo, que só existe em Linux, macOS e WSL. Rode a demonstração no WSL (ex.: wsl -- python3 demo.py) ou em Linux/macOS. Nenhum arquivo foi criado.
```

**Python 3 e dependências.** A única dependência de execução é `cryptography==49.0.0` (`requirements.txt`); o `pytest` só é necessário para a suíte de testes. Na raiz do projeto (a pasta que contém `pyproject.toml` e `demo.py`):

```bash
pip install -r requirements.txt pytest
```

Em Ubuntu/WSL, o `pip` do sistema pode recusar a instalação global; use um ambiente virtual fora da pasta do projeto:

```bash
python3 -m venv ~/venv-urna
source ~/venv-urna/bin/activate
pip install -r requirements.txt pytest
```

Onde o comando `python` não existir (Ubuntu/WSL fora do ambiente virtual), use `python3` em todos os comandos deste roteiro.

**Checagem antes da apresentação** (no mesmo computador e terminal da apresentação):

```bash
python -m pytest -q tests/demo   # testes do roteiro da demonstração
python demo.py                   # deve terminar com "RESULTADO: DEMONSTRAÇÃO OK" e código 0
```

---

## 2. Comandos

| Comando | O que faz |
|---|---|
| `python demo.py` | Executa as 9 etapas de uma vez. Saída em `data/demo/`. |
| `python demo.py --pause` | **Recomendado na apresentação.** Depois de cada etapa de 1 a 8, mostra `[Enter] próxima etapa` e espera o Enter. O tempo parado não entra no "Tempo de execução", e o resumo acrescenta `; pausas: X s`. |
| `python demo.py --output-dir <dir>` | Grava em outro diretório (padrão: `data/demo/`). Pode ser combinado com `--pause`. |
| `python -m src.auditor.auditor data/demo/public` | (Opcional, depois de uma execução) roda o auditor como **processo separado** sobre os dados válidos: imprime `Resultado: ELEIÇÃO VÁLIDA` e sai com 0. |
| `python -m src.auditor.auditor data/demo/tampered_public` | (Opcional) o mesmo sobre a cópia adulterada: `Resultado: ELEIÇÃO INVÁLIDA (dados adulterados ou inconsistentes)` e saída 1. |

**Diretório de saída.** Cada execução apaga e recria o diretório, com três subpastas:

- `public/`: dados públicos que o auditor lê (`election.json`, `voters.json`, `bulletin_board.jsonl`, `aggregate_ciphertexts.json`, `authority_partials.json`, `result.json`), além de `accepted_ballots.json` (estado da eleição) e `server_public_key.pem` (chave pública que assina os recibos);
- `private/`: `authority_1.key`, `authority_2.key` e `authority_3.key`, com os `x_i` (nunca publicados; `data/demo/` está no `.gitignore`);
- `tampered_public/`: cópia de `public/` com uma cédula adulterada (etapas 8 e 9).

Por segurança, o demo só apaga um diretório existente se ele estiver vazio ou tiver o marcador `.urna_demo` (criado pelo próprio demo), e recusa `data/public/`, `data/private/`, a raiz do projeto e qualquer diretório que os contenha.

**Códigos de saída**

| Código | Significado | Mensagem (stderr) |
|---|---|---|
| `0` | As 9 etapas conferiram. A última linha do resumo é `RESULTADO: DEMONSTRAÇÃO OK`. | — |
| `1` | Alguma etapa divergiu do esperado (ou lançou exceção). O demo para nessa etapa, marca as seguintes como `(não executada)` e imprime `RESULTADO: FALHOU`. | `ERRO: a etapa N divergiu do esperado: …` |
| `2` | Diretório de saída recusado (ex.: `--output-dir data/public`, ou diretório não vazio sem `.urna_demo`). Nada é apagado. | `ERRO: diretório de saída … sobrepõe …` ou `ERRO: … não está vazio e não foi criado pelo demo (falta .urna_demo); escolha outro --output-dir` |
| `3` | Plataforma sem `fcntl` (Windows nativo). Nenhum arquivo é criado. | `ERRO: o quadro público (src/bulletin_board/board.py) usa fcntl …` |
| `130` | Interrompido pelo usuário: Ctrl+C em qualquer momento ou Ctrl+D (fim da entrada) no prompt `[Enter] próxima etapa` do `--pause`. Sai sem traceback; o diretório de saída fica como estava e é recriado na próxima execução. | `Demonstração interrompida pelo usuário` |

Nos códigos 2 e 130, o cabeçalho do demo (linhas `═══`) já foi impresso antes da mensagem. O 130 segue a convenção do shell para término por Ctrl+C (128 + SIGINT) e é diferente de 0 a 3, para que um script que chame o demo distinga interrupção de falha.

**Tempo de execução.** Medido em três execuções seguidas (Linux, Python 3.13): **10,98 s, 11,05 s e 11,26 s** de "Tempo de execução" (cerca de 11,1–11,4 s de relógio, incluindo o início do Python). O script compara com o alvo `< 30 s`. A etapa mais lenta é a 7 (~3,7 s: cada parcela tem prova de Chaum-Pedersen verificada três vezes), seguida da 6 (~1,8 s) e da 1 (~1,5 s, Miller-Rabin em `p` e `q`). Com `--pause`, a etapa seguinte só começa depois do Enter: espere o `Obtido:` aparecer antes de comentar o resultado.

---

## 3. Cronograma de 10 minutos

O script roda em cerca de 11 s; o tempo abaixo é o da **explicação**, com `python demo.py --pause`. A coluna "Responsável" é uma sugestão de divisão equilibrada entre os quatro integrantes listados no README (cerca de 2,5 min cada), agrupando etapas do mesmo tema; a equipe pode ajustá-la.

| # | Etapa | Tempo de fala | Acumulado | Responsável (sugestão) |
|---|---|---|---|---|
| — | Abertura: objetivo, cenário e comando `python demo.py --pause` | 0:40 | 0:40 | Carlos Victor Albuquerque Oliveira |
| 1 | Configuração da eleição | 0:45 | 1:25 | Carlos Victor Albuquerque Oliveira |
| 2 | Autoridades e eleitores | 1:10 | 2:35 | Carlos Victor Albuquerque Oliveira |
| 3 | Votos válidos e recibos | 1:20 | 3:55 | Eduardo Luna Scalassara |
| 4 | Tentativa de voto duplicado | 0:35 | 4:30 | Eduardo Luna Scalassara |
| 5 | Encerramento da votação | 0:35 | 5:05 | Eduardo Luna Scalassara |
| 6 | Apuração sem uma das autoridades | 1:10 | 6:15 | Leandro Coelho da Silva |
| 7 | Apuração com todas as autoridades | 1:15 | 7:30 | Leandro Coelho da Silva |
| 8 | Auditoria dos dados válidos e adulteração da cópia | 1:00 | 8:30 | Pedro Afonso Custodio De Lima |
| 9 | Auditoria da cópia adulterada | 0:50 | 9:20 | Pedro Afonso Custodio De Lima |
| — | Fechamento: resumo, totais, nota sobre a prova 0/1 e tempo | 0:40 | 10:00 | Pedro Afonso Custodio De Lima |

Divisão por tema: Carlos (grupo e chaves, 2:35), Eduardo (cédula, recibo e estados, 2:30), Leandro (apuração conjunta, 2:25), Pedro (auditoria e limitações, 2:30). Cada integrante deve conseguir explicar a própria etapa e responder às perguntas da seção 5 ligadas a ela; todos devem conhecer a pergunta sobre a prova 0/1, que é a limitação assumida.

**Abertura (sugestão de fala).** "Vamos rodar a eleição completa com o código real do projeto: dois candidatos, três eleitores e três autoridades. O script confere cada etapa sozinho e para se algo divergir. O cenário é fixo, eleitor-1 e eleitor-3 votam em Alice e eleitor-2 em Bob, então o resultado esperado é Alice 2, Bob 1."

**Fechamento (sugestão de fala).** Apontar no resumo os nove `[✔]`, a linha `Totais: Alice 2, Bob 1   (esperado: Alice 2, Bob 1)` e o `Tempo de execução`. Ler a segunda `Nota:` e dizer que a ausência da prova 0/1 é uma limitação assumida pela equipe, mitigada só em parte pela verificação da soma dos totais (pergunta 5.8).

---

## 4. As 9 etapas

Cada etapa imprime o título `[N/9]`, um parágrafo `O que acontece:`, a linha `Esperado:`, os detalhes (`·`) e a linha `Obtido:` com ✔ ou ✘ e o tempo. Todas as funções citadas estão em `demo.py` (funções `_step1_configuration` a `_step9_audit_tampered`) ou nos módulos indicados.

### Etapa 1 — Configuração da eleição

**O que mostrar na tela**

```text
[1/9] Configuração da eleição
    · grupo RFC3526-MODP-14: p = 0xffffffffffffffff… (2048 bits)
    · q = (p-1)/2 = 0x7fffffffffffffff… (2047 bits)   g = 2
    · Miller-Rabin (32 rodadas) em p e q; g^q ≡ 1 (mod p)
    · candidatos: Alice, Bob   eleição: 'demo-t15'
  Obtido:   ✔ grupo validado (p 2048 bits); etapa CADASTRO; candidatos Alice, Bob   (1.52 s)
```

**O que falar.** Usamos um grupo público e padronizado, o MODP de 2048 bits do RFC 3526, sem gerar parâmetros próprios. O `p` é um primo seguro: `p = 2q + 1`, com `q` também primo. O programa confere a primalidade de `p` e de `q` com Miller-Rabin e confere que `g = 2` está no subgrupo de ordem `q`. Toda a criptografia de votos acontece nesse subgrupo. Criar a eleição já valida grupo e candidatos, por isso ela nasce na etapa CADASTRO.

**Conceito criptográfico.** Grupo multiplicativo módulo `p`, com `p` primo seguro de 2048 bits, e subgrupo de ordem prima `q = (p − 1)/2` (os resíduos quadráticos), gerado por `g = 2`:

```text
g^q ≡ 1 (mod p)        x pertence ao subgrupo  ⇔  x^q ≡ 1 (mod p)
```

Trabalhar no subgrupo de ordem prima evita que um valor fora dele vaze informação (por exemplo, o símbolo de Legendre) e garante que todo expoente pode ser reduzido módulo `q`. Por isso o servidor, o quadro e o auditor recusam cifras com `c^q ≢ 1`.

**Arquivos e funções**

- `src/crypto/group/parameters.py`: `rfc3526_group14()` e `DEFAULT_PARAMETERS` (`p` do RFC, `q = (p-1)//2`, `g = 2`).
- `src/crypto/group/operations.py`: `validate_parameters(..., check_primality=True)` (p ≥ 2048 bits, `q | p−1`, `g^q ≡ 1`) e `is_probable_prime` (Miller-Rabin, 32 rodadas).
- `src/election/election.py`: `Election(...)` valida identificador, grupo e candidatos; o objeto começa em `ElectionState.CADASTRO` (`src/election/states.py`, `NEXT_STATE`).
- Arquivo criado: `public/election.json` (por enquanto só com os candidatos).

**Resultado esperado.** `✔`; grupo de 2048 bits validado, eleição em `CADASTRO`, candidatos `Alice, Bob`.

### Etapa 2 — Autoridades e eleitores

**O que mostrar na tela**

```text
[2/9] Autoridades e eleitores
    · autoridade 1: h_1 = 0x4cb36638e4244e2e… (2047 bits)
    · autoridade 2: h_2 = 0x252c55d4af26433b… (2046 bits)
    · autoridade 3: h_3 = 0xbb6e09c83af9de02… (2048 bits)
    · chave conjunta h = h_1·h_2·h_3 mod p = 0xe77bfbe199cf7f12… (2048 bits)
    · eleitor-1: RSA 3072 bits (só a chave pública é cadastrada)
    · eleitor-2: RSA 3072 bits (só a chave pública é cadastrada)
    · eleitor-3: RSA 3072 bits (só a chave pública é cadastrada)
    · chaves privadas em private/: authority_1.key, authority_2.key, authority_3.key
  Obtido:   ✔ 3 autoridades, h conjunta conferida, 3 eleitores; cadastro congelado   (0.99 s)
```

**O que falar.** Cada autoridade sorteia sua parte secreta `x_i` e publica só `h_i = g^x_i`. A chave pública da eleição é o produto `h = h_1·h_2·h_3`, que corresponde ao expoente `x_1 + x_2 + x_3`, mas essa soma nunca é calculada em lugar nenhum. Os `x_i` ficam só em `private/`; o script confere que nenhum deles aparece nos arquivos públicos. Cada eleitor tem um par RSA de 3072 bits e cadastra apenas a chave pública. No fim, o cadastro é congelado e a chave conjunta é publicada em `election.json`.

**Conceito criptográfico.** Chave conjunta multiplicativa (n de n):

```text
x_i ∈ [2, q−1] aleatório        h_i = g^x_i mod p
h = ∏ h_i mod p = g^(x_1 + x_2 + x_3) mod p
```

Ninguém conhece `x = Σ x_i`: para decifrar seria preciso a colaboração de todas as autoridades (etapas 6 e 7). Além disso, o servidor recebe um par RSA próprio (3072 bits) para assinar recibos; a chave privada fica só em memória e a pública vai para `public/server_public_key.pem`.

**Arquivos e funções**

- `src/authorities/authority.py`: `Authority.generate` (sorteia `x_i` com `secrets` e grava `authority_{id}.key` com permissão 0600), `Authority.public_key()` (só `id` e `h_i`), `compute_joint_public_key` e `publish_joint_public_key` (grava grupo, autoridades, eleitores e `joint_public_key` em `election.json`).
- `src/server/registration.py`: `Registration.register_authority`, `register_voter`, `freeze`, `export_public_data` (só aceita inclusões em `CADASTRO`).
- `src/crypto/signatures.py`: `generate_signing_key(3072)`; `src/crypto/keys.py`: `public_key_to_pem`.
- `src/bulletin_board/board.py`: `BulletinBoard.create` (quadro vazio); `src/server/voting.py`: `VotingService` e `board_publisher_for`.
- No demo: `VoterClient.generate` (cliente do eleitor, que não existe em `src/`). Os objetos `Authority` são descartados; as etapas 6 e 7 recarregam cada `x_i` de `private/`, simulando o processo de cada autoridade.
- Arquivos criados: `private/authority_{1,2,3}.key`, `public/election.json` (completo), `public/voters.json`, `public/bulletin_board.jsonl` (vazio), `public/server_public_key.pem`.

**Resultado esperado.** `✔`; três `h_i` distintos no subgrupo, `h` publicado igual a `h_1·h_2·h_3 mod p`, três eleitores, nenhuma chave privada nos dados públicos e cadastro congelado.

### Etapa 3 — Votos válidos e recibos

**O que mostrar na tela**

```text
[3/9] Votos válidos e recibos
    · eleitor-1 (vota Alice) → recibo #0 ca538b694d99bcaa…  c1[Alice] = 0x8b574ba770353efa… (2048 bits)
    · eleitor-2 (vota Bob) → recibo #1 c19cf6e649c54f3f…  c1[Alice] = 0x96fb4f35e8257c2d… (2048 bits)
    · eleitor-3 (vota Alice) → recibo #2 e2dbd99e400cc240…  c1[Alice] = 0x32d93da350dbad27… (2046 bits)
    · quadro #0: previous 1054a8bf1c9288b0… → hash 280a6e435a0389a6…
    · quadro #1: previous 280a6e435a0389a6… → hash ae87e9144b038528…
    · quadro #2: previous ae87e9144b038528… → hash 84beb3663a0fb814…
    · recibos assinados pelo servidor (RSA-PSS) conferidos no quadro: 3/3; checkpoint 3 registros, hash final 84beb3663a0fb814…
  Obtido:   ✔ 3 cédulas aceitas e no quadro; 3 recibos assinados e conferidos pelos eleitores   (0.75 s)
```

**O que falar.** A votação é aberta e cada eleitor cifra um bit por candidato: 1 para o escolhido e 0 para o outro, sempre com um `r` aleatório novo, então ninguém distingue as cédulas olhando as cifras. A cédula é assinada com RSA-PSS e o servidor confere eleitor, voto único, assinatura e pertencimento ao subgrupo. Cada cédula aceita vira um registro do quadro público, cujo `previous` é o hash do registro anterior: mostrem como o hash de um registro reaparece como `previous` do seguinte. O servidor assina um recibo que aponta índice e hash do registro, e cada eleitor confere o próprio recibo contra o quadro; o recibo não contém o voto nem o `r`.

**Conceito criptográfico**

```text
ElGamal exponencial:  (c1, c2) = (g^r, g^m · h^r) mod p,   m ∈ {0, 1},  r ∈ [1, q−1]
Assinatura da cédula: RSA-PSS (SHA-256, MGF1-SHA-256, salt de 32 bytes)
                      sobre "URNA_ONLINE:BALLOT:v1\0" ‖ JSON canônico da cédula
Cadeia de hashes:     hash_0 anterior = SHA-256("URNA_ONLINE:BOARD:GENESIS:v1\0" ‖ election_id)
                      hash_i = SHA-256("URNA_ONLINE:BOARD:RECORD:v1\0" ‖ JSON canônico de
                               {schema_version, index, previous_hash = hash_(i−1), ballot, signature})
```

Há dois recibos. O **recibo da eleição** (`recibo #0 ca538b…` na tela) é `SHA-256("URNA_ONLINE:ELECTION-RECEIPT:v1\0" ‖ cédula canônica ‖ "\n" ‖ assinatura)`, recalculável por qualquer um a partir do registro do quadro. O **recibo assinado** pelo servidor é `{schema_version, election_id, voter_id, record_index, record_hash}` assinado com RSA-PSS sob o domínio `URNA_ONLINE:RECEIPT:v1`. Os domínios distintos impedem reaproveitar uma assinatura de cédula como recibo e vice-versa. O primeiro `previous` (`1054a8bf1c9288b0…`) é o hash inicial da eleição `demo-t15` e é igual em toda execução. Na demo, o checkpoint usado pelos eleitores (tamanho 3 e hash final) vem da própria instância do quadro; numa implantação real ele precisaria vir de uma fonte independente (pergunta 5.6).

**Arquivos e funções**

- `src/crypto/elgamal/cipher.py`: `encrypt_bit` (recusa `m ∉ {0, 1}`; o demo descarta o `r`).
- `src/crypto/ballots.py`: `canonical_ballot_bytes`, `sign_ballot`, `verify_signed_ballot` (o único formato de cédula).
- `src/server/voting.py`: `VotingService.open_voting`, `receive_ballot` (publica no quadro só depois da aceitação).
- `src/election/election.py`: `Election.open_voting` (cadastro congelado, ≥ 3 autoridades, `h` recalculado igual ao publicado), `submit_ballot` (etapa → formato → elegibilidade → voto único → assinatura → subgrupo e reuso de `c1`) e `compute_receipt`.
- `src/bulletin_board/board.py`: `BulletinBoard.append` (reverifica assinatura, elegibilidade e unicidade sob `flock` exclusivo e grava com `fsync`), `records`, `checkpoint`.
- `src/bulletin_board/hash_chain.py`: `genesis_hash`, `hash_record`, `make_record`, `verify_board`.
- `src/server/receipts.py`: `issue_receipt`; `src/crypto/receipts.py`: `sign_receipt`, `verify_receipt_in_board`.
- Arquivos: `public/accepted_ballots.json` e três linhas em `public/bulletin_board.jsonl`.

**Resultado esperado.** `✔`; etapa `VOTACAO_ABERTA`, recibos com índices 0, 1 e 2, três registros no quadro, recibos recalculáveis a partir do quadro, 3/3 recibos assinados conferidos e seis `c1` distintos.

### Etapa 4 — Tentativa de voto duplicado

**O que mostrar na tela**

```text
[4/9] Tentativa de voto duplicado
    · eleitor-2 envia nova cédula (voto Alice), assinada corretamente
    · motivo: DuplicateVoteError: eleitor 'eleitor-2' já votou
  Obtido:   ✔ rejeitada — DuplicateVoteError: eleitor 'eleitor-2' já votou   (0.14 s)
```

**O que falar.** O eleitor-2 tenta votar de novo, agora em Alice, com uma cédula válida e corretamente assinada. O servidor guarda quem já votou e rejeita a cédula antes de qualquer efeito: nem chega a verificar a assinatura. O quadro público continua byte a byte igual e o voto original em Bob é preservado.

**Conceito.** Unicidade por eleitor, garantida em camadas: `Election.submit_ballot` consulta o conjunto de quem já votou (sob uma trava, para que dois envios simultâneos não passem juntos); `BulletinBoard.append` repete a checagem antes de gravar; e o auditor confere a unicidade no quadro (verificação b). A autenticação do eleitor vem da assinatura RSA-PSS com a chave cadastrada.

**Arquivos e funções.** `src/election/election.py`: `Election.submit_ballot` (passo 4, `DuplicateVoteError`); `src/server/voting.py`: `VotingService.receive_ballot` (rejeições nunca chegam ao quadro); `src/bulletin_board/board.py`: `BulletinBoard.append` (defesa local).

**Resultado esperado.** `✔`; `DuplicateVoteError`, quadro inalterado, continuam 3 cédulas aceitas e a cédula original do eleitor-2 está preservada.

### Etapa 5 — Encerramento da votação

**O que mostrar na tela**

```text
[5/9] Encerramento da votação
    · etapa: VOTACAO_ABERTA → ENCERRADA
    · eleitor-3 tenta votar depois do encerramento (a etapa é conferida antes de tudo)
    · motivo: VotingClosedError: cédulas só são aceitas em VOTACAO_ABERTA; etapa atual: ENCERRADA
  Obtido:   ✔ etapa ENCERRADA; voto tardio rejeitado — VotingClosedError   (0.14 s)
```

**O que falar.** A eleição segue uma máquina de estados que só anda para a frente: CONFIGURACAO, CADASTRO, VOTACAO_ABERTA, ENCERRADA, APURACAO e AUDITADA. Encerrada a votação, a primeira coisa conferida em qualquer cédula é a etapa, então o voto tardio é recusado. Ainda não existe resultado publicado: a apuração só pode começar na etapa seguinte.

**Conceito.** Controle de fluxo, não criptografia: `NEXT_STATE` define uma única sucessora para cada etapa, sem arestas para trás nem atalhos; cada transição é gravada em disco antes de ser aplicada em memória. As funções de apuração (`publish_aggregate`, parcelas, coletor e combinação), quando recebem a etapa (o demo sempre passa `election.current_state`), recusam qualquer etapa diferente de `APURACAO` com `TallyStateError`.

**Arquivos e funções.** `src/election/states.py`: `ElectionState`, `NEXT_STATE`; `src/election/election.py`: `close_voting`, `_advance`, `submit_ballot` (passo 1, `VotingClosedError`); `src/server/voting.py`: `VotingService.close_voting`.

**Resultado esperado.** `✔`; etapa `ENCERRADA`, voto tardio rejeitado com `VotingClosedError`, quadro inalterado e nenhum `result.json`.

### Etapa 6 — Apuração sem uma das autoridades

**O que mostrar na tela**

```text
[6/9] Apuração sem uma das autoridades
    · produto Alice: C1 = 0x4b505ed4b997dda7… (2047 bits)  C2 = 0xb96e41685ba23f7a… (2048 bits)
    · produto Bob: C1 = 0xeb8e5f4f1c5df59c… (2048 bits)  C2 = 0xe4c7eaa29b183c68… (2048 bits)
    · parcelas recebidas: autoridades 1, 2; ausente: 3
    · motivo: MissingAuthorityShareError: faltam parcelas das autoridades ['3']
  Obtido:   ✔ apuração interrompida — MissingAuthorityShareError: faltam parcelas das autoridades ['3']   (1.82 s)
```

**O que falar.** A eleição passa para APURACAO e o servidor multiplica as cifras de cada candidato, o que soma os votos sem decifrar nenhuma cédula. Para tirar a "máscara" `h^R` do produto, cada autoridade precisa contribuir com uma parcela calculada com seu `x_i`. Aqui só as autoridades 1 e 2 participam. A apuração falha com um erro explícito que aponta a autoridade 3, e nenhum resultado é publicado.

**Conceito criptográfico.** Produto homomórfico e decifração conjunta n de n:

```text
(C1, C2) = (∏ c1, ∏ c2) = (g^R, g^T · h^R) mod p,   R = Σ r,  T = Σ m  (total do candidato)
d_i = C1^x_i mod p
∏_{todas} d_i = C1^(x_1+x_2+x_3) = h^R
∏_{1,2}   d_i = C1^(x_1+x_2)  ≠ h^R  →  C2 · (d_1·d_2)^−1 = g^T · C1^x_3   (inútil sem x_3)
```

O coletor exige a parcela de **todas** as autoridades cadastradas (não é um esquema de limiar). As parcelas recebidas são verificadas (prova de Chaum-Pedersen, etapa 7) antes de se constatar a falta.

**Arquivos e funções**

- `src/election/election.py`: `start_tally` (`ENCERRADA → APURACAO`).
- `src/authorities/partial_decryption.py`: `publish_aggregate` / `build_aggregate` (com a etapa informada, exige `APURACAO`; grava `aggregate_ciphertexts.json` com `ballot_count = 3`), `load_public_json`, `compute_authority_partials` (no processo da autoridade, após `Authority.load` da chave em `private/`; antes de decifrar, confere o agregado contra `public/bulletin_board.jsonl`), `combine_and_decrypt_result` (lança `MissingAuthorityShareError` sem gravar nada).
- `src/crypto/homomorphic/tally.py`: `aggregate_ciphertexts`.

**Resultado esperado.** `✔`; etapa `APURACAO`, agregado com as 3 cédulas, `MissingAuthorityShareError` citando `'3'` e nenhum `result.json`.

### Etapa 7 — Apuração com todas as autoridades

**O que mostrar na tela**

```text
[7/9] Apuração com todas as autoridades
    · servidor malicioso envia à autoridade 1 só a cédula de eleitor-1 como agregado (ballot_count 1)
    · recusa: AggregateVerificationError: agregado recusado: difere do recalculado a partir do quadro público (3 cédula(s)): ballot_count informado 1, esperado 3; C1 e C2 de 'Alice'; C1 e C2 de 'Bob'
    · autoridade 1: d(Alice) = 0xc1cc925bbf86… (2048 bits)  d(Bob) = 0x3adf1903c536… (2046 bits)  prova ✔
    · autoridade 2: d(Alice) = 0x2aaff73b140b… (2046 bits)  d(Bob) = 0x17a4ecd3a19f… (2045 bits)  prova ✔
    · autoridade 3: d(Alice) = 0x114acff03aa9… (2045 bits)  d(Bob) = 0xe73d4cf51ecf… (2048 bits)  prova ✔
    · Alice: 2 voto(s) (esperado 2)
    · Bob: 1 voto(s) (esperado 1)
    · limite de cada total: [0, 3] (cédulas aceitas); soma dos totais: 3 = 3 cédulas
  Obtido:   ✔ totais publicados: Alice 2, Bob 1   (3.73 s)
```

(Esta etapa leva cerca de 4 s para aparecer depois do Enter.)

**O que falar.** Primeiro, a demo encena um servidor malicioso: ele envia à autoridade 1 só a cifra da cédula do eleitor-1, como se fosse o agregado. Se a autoridade decifrasse, o voto do eleitor-1 apareceria. Ela não confia no servidor: lê o quadro público, confere cadeia e assinaturas, recalcula o produto das 3 cédulas e o número de cédulas, vê que nada confere e recusa com `AggregateVerificationError`, sem usar o `x_1` (pergunta 5.11, inclusive o que essa conferência não cobre). Se a recusa não acontecesse, a etapa divergiria e a demo terminaria com código 1. Agora, com o agregado correto, as três autoridades enviam suas parcelas, uma por candidato, cada uma com uma prova de Chaum-Pedersen. A prova mostra que a autoridade usou o mesmo `x_i` da chave pública que cadastrou, sem revelar o `x_i`; o servidor só aceita parcelas com prova válida. Multiplicando as três parcelas, o servidor obtém `h^R`, divide `C2` por esse valor e chega a `g^T`. Como `T` só pode estar entre 0 e o número de cédulas aceitas (3, o mesmo limite que o auditor usa; numa eleição com abstenção, menor que o número de eleitores), basta testar `g^0, g^1, g^2, g^3` para encontrar o total. Antes de publicar, a apuração confere que a soma dos totais é igual ao número de cédulas, porque cada cédula honesta tem exatamente um voto. O resultado Alice 2, Bob 1 é publicado em `result.json`.

**Conceito criptográfico**

```text
Parcela:        d_i = C1^x_i mod p
Prova (Chaum-Pedersen, Fiat-Shamir, mostra log_g(h_i) = log_C1(d_i)):
  autoridade:   w aleatório,  a1 = g^w,  a2 = C1^w
                c = SHA-256(domínio "URNA_ONLINE/chaum-pedersen/v1", eleição, autoridade,
                            candidato, p, q, g, h_i, C1, d_i, a1, a2) mod q
                s = w + c·x_i mod q
  verificador:  g^s ≡ a1 · h_i^c   e   C1^s ≡ a2 · d_i^c   (mod p)
Combinação:     g^T = C2 · (∏ d_i)^−1 mod p
Logaritmo discreto limitado: menor T ∈ [0, nº de cédulas aceitas] com g^T ≡ g^T calculado
Soma:           Σ T_candidato = nº de cédulas (sem voto em branco); senão, nada é publicado
```

Cada prova é verificada três vezes: pela própria autoridade (autoverificação), pelo coletor do servidor (`submit`) e de novo em `combine_and_decrypt_result`. O total ainda é conferido com `pow(g, T, p)`. O limite `max_votes` vem do `ballot_count` de `aggregate_ciphertexts.json` (cédulas que entraram no produto), não de `len(voters)`; se a soma dos totais divergir, `combine_and_decrypt_result` lança `InconsistentTotalsError` e não grava `result.json`.

**Arquivos e funções**

- `src/authorities/partial_decryption.py`: `compute_authority_partials` (`board_path` obrigatório, `expected_checkpoint` opcional), `_verify_aggregate_against_board`, `AggregateVerificationError`, `_prove_share`, `_verify_share`, `_challenge`, `PartialDecryptionCollector` (`submit`, `is_complete`, `save`), `combine_and_decrypt_result`, `_aggregate_ballot_count`, `_check_totals_sum`, `crypto_discrete_log`.
- `src/auditor/board_tally.py` (mesmo código de recálculo do auditor): `record_ciphertexts`, `register_ciphertexts` (subgrupo e `c1` repetido), `aggregate_columns`; `src/bulletin_board/hash_chain.py`: `read_records`, `verify_board`, `make_checkpoint`.
- `src/crypto/group/operations.py`: `inverse_mod`; `src/crypto/elgamal/cipher.py`: `bounded_discrete_log` (busca linear em `[0, maximum]`).
- Arquivos: `public/authority_partials.json` (parcelas e provas, só dados públicos) e `public/result.json` (`totals`, `authorities`, `max_votes = 3`, igual ao número de cédulas).

**Resultado esperado.** `✔`; o agregado forjado (só a cédula do eleitor-1) é recusado com `AggregateVerificationError`; as três autoridades participaram, `result.json` publicado, totais `Alice 2, Bob 1`, limite dos totais igual a 3 cédulas e soma dos totais igual a 3 cédulas.

### Etapa 8 — Auditoria dos dados válidos e adulteração da cópia

**O que mostrar na tela**

```text
[8/9] Auditoria dos dados válidos e adulteração da cópia
    · ✔ Dados públicos (election.json / voters.json)
    · ✔ a) Cadeia de hashes do quadro público
    · ✔ b) Elegibilidade e unicidade dos eleitores
    · ✔ c) Assinaturas e cifras das cédulas
    · ✔ d) Produto homomórfico das cifras
    · ✔ e) Parcelas das autoridades e resultado
    · cópia tampered_public/: entrada 1 (eleitor-2), c2[Alice] 0xd5970431fd92… (2048 bits) → 0xab2e0863fb25… (2048 bits) (× g = +1 voto)
  Obtido:   ✔ auditor: ELEIÇÃO VÁLIDA (6/6 verificações); cópia adulterada criada   (1.15 s)
```

**O que falar.** O auditor recebe só o caminho de `public/`: não recebe objetos do servidor, não importa o código do servidor nem das autoridades e não lê `private/`. Ele refaz tudo que dá para refazer com dados públicos: a cadeia de hashes, as assinaturas dos eleitores, o produto das cifras e as provas das autoridades, e confere o total publicado sem precisar de chave privada. Com as seis verificações aprovadas, a eleição passa para AUDITADA. Em seguida simulamos um ataque numa cópia: multiplicamos o `c2` de Alice da cédula do eleitor-2 por `g`, o que transformaria o voto 0 em 1, sem refazer hash nem assinatura.

**Conceito criptográfico.** Verificação pública, sem segredo:

```text
d) (∏ c1, ∏ c2) recalculado do quadro  ==  aggregate_ciphertexts.json
e) provas de Chaum-Pedersen reverificadas contra o agregado RECALCULADO;
   para cada candidato:  C2 ≡ g^T · ∏ d_i (mod p),  com T de result.json e 0 ≤ T ≤ nº de cédulas
Adulteração: c2' = c2 · g = g^(m+1) · h^r   (cifra válida de m+1)
```

Conferir `C2 ≡ g^T·∏d_i` é mais barato que decifrar: o auditor não precisa calcular logaritmo discreto.

**Arquivos e funções**

- `src/auditor/auditor.py`: `Auditor.run` e as verificações `_load_public_context` (dados públicos), `_check_hash_chain` (a), `_check_eligibility` (b), `_check_signatures` (c), `_check_aggregate` (d), `_check_result` (e), além de `_verify_share`/`_challenge` reimplementados a partir do protocolo público.
- `demo.py`: `audit_public_dir`, `directory_digest` (prova que `public/` não mudou), cópia com `shutil.copytree` e regravação da linha adulterada.
- `src/election/election.py`: `mark_audited` (`APURACAO → AUDITADA`).

**Resultado esperado.** `✔`; auditor aprova os dados válidos (6/6), eleição `AUDITADA`, cópia adulterada diferente do original e `public/` intacto (mesmo SHA-256 do diretório).

### Etapa 9 — Auditoria da cópia adulterada

**O que mostrar na tela**

```text
[9/9] Auditoria da cópia adulterada
    · ✔ Dados públicos (election.json / voters.json)
    · ✘ a) Cadeia de hashes do quadro público
    ·     - entrada 1: hash não corresponde ao conteúdo do registro (registro alterado)
    · ✔ b) Elegibilidade e unicidade dos eleitores
    · ✘ c) Assinaturas e cifras das cédulas
    ·     - entrada 1: assinatura do eleitor 'eleitor-2' inválida (cédula adulterada ou forjada)
    · ✘ d) Produto homomórfico das cifras
    ·     - aggregate_ciphertexts.json: C2 de 'Alice' difere do produto recalculado do quadro
    · ✘ e) Parcelas das autoridades e resultado
    ·     - result.json: total publicado de 'Alice' (2) não corresponde à decifração conjunta do produto homomórfico
  Obtido:   ✔ ELEIÇÃO INVÁLIDA — falharam: hash_chain, signatures_proofs, homomorphic_aggregate, tally_result (adulteração na entrada 1)   (1.03 s)
```

**O que falar.** O mesmo auditor, rodado sobre a cópia adulterada, reprova a eleição e aponta a entrada 1. A cadeia acusa que o conteúdo do registro não bate mais com o hash gravado, e a assinatura do eleitor-2 deixou de valer porque a cifra assinada mudou. Mesmo que o atacante recalculasse os hashes, que são públicos, a assinatura continuaria falhando, porque ele não tem a chave privada do eleitor. Como a cifra mudou, o produto homomórfico e a conferência do resultado também falham. O `✔` em "Obtido" significa que a demo obteve o esperado: a adulteração foi detectada.

**Conceito.** Integridade em camadas: o hash de cada registro cobre a cédula e a assinatura; a assinatura RSA-PSS cobre a cédula; o produto homomórfico e `C2 ≡ g^T·∏d_i` amarram o resultado às cifras do quadro. Só a entrada 1 aparece na cadeia porque o elo da entrada 2 é comparado com o hash **gravado** da entrada 1, que não mudou. Dados públicos e elegibilidade continuam corretos, pois o cadastro e os `voter_id` não foram alterados.

**Arquivos e funções.** `src/auditor/auditor.py` (as mesmas verificações da etapa 8); `src/bulletin_board/hash_chain.py`: `hash_record`, `genesis_hash`; `src/crypto/ballots.py`: `verify_signed_ballot`; `src/crypto/homomorphic/tally.py`: `aggregate_ciphertexts`.

**Resultado esperado.** `✔`; auditor reprova a cópia; `hash_chain` e `signatures_proofs` apontam a entrada 1; `homomorphic_aggregate` e `tally_result` também falham; `public/` continua intacto.

---

## 5. Perguntas prováveis da banca

### 5.1 Por que ElGamal exponencial? Por que o logaritmo discreto é viável aqui?

Porque, com a mensagem no expoente (`g^m`), multiplicar cifras soma os votos: `(g^r1, g^m1·h^r1) · (g^r2, g^m2·h^r2) = (g^(r1+r2), g^(m1+m2)·h^(r1+r2))`. Assim o servidor apura sem decifrar nenhuma cédula. O preço é que a decifração devolve `g^T`, e não `T`. Resolver logaritmo discreto em geral num grupo de 2048 bits é inviável, mas aqui `T` é pequeno e limitado: `bounded_discrete_log` testa `g^0, g^1, …` até o número de cédulas aceitas (`max_votes = 3` na demo, no máximo 4 tentativas; o auditor usa o mesmo limite). O custo é linear no número de cédulas; para eleições grandes seria preciso algo como baby-step giant-step, que não está implementado. O auditor nem precisa do logaritmo: ele confere `C2 ≡ g^T·∏d_i`.

### 5.2 Por que o servidor não consegue decifrar votos individuais?

Porque ele não tem nenhum `x_i` e a chave privada completa `x = Σ x_i` nunca é calculada ou guardada em lugar nenhum: o servidor só conhece `h = ∏ h_i`. Decifrar `(g^r, g^m·h^r)` exige `h^r = (g^r)^x`, e, sob a hipótese de Diffie-Hellman decisional no subgrupo de ordem `q`, as cifras não revelam `m`. O cliente descarta o `r` (que também não entra no recibo nem no quadro), e cada cédula usa `r` novo, o que o servidor e o auditor conferem (nenhum `c1` repetido). Dois cuidados para ser preciso: (1) na demo, autoridades e servidor rodam no mesmo processo e as chaves ficam em `data/demo/private/` no mesmo disco; a separação é simulada por arquivos; (2) as autoridades só decifram um agregado que confira com o quadro público que elas mesmas leem, mas confiam nesse quadro e em `election.json`: o que isso garante e o que continua aberto está na pergunta 5.11.

### 5.3 E se uma autoridade faltar? E se todas conspirarem?

Faltando qualquer autoridade, a apuração para: o produto das parcelas não cancela `h^R` e `combine_and_decrypt_result` lança `MissingAuthorityShareError` sem publicar nada (etapa 6). O esquema é n de n, sem limiar (não há Shamir/threshold), então perder um `x_i` impede a apuração; isso está nas limitações do README. Se **todas** conspirarem, elas podem somar `x = Σ x_i` e decifrar qualquer cédula individual, quebrando o sigilo; qualquer subconjunto menor não consegue. Mesmo assim, não conseguem falsificar o resultado: cada `d_i` precisa de prova de Chaum-Pedersen ligada ao `h_i` cadastrado, e o auditor confere `C2 ≡ g^T·∏d_i` contra o quadro.

### 5.4 O que a prova de Chaum-Pedersen das parcelas garante? Por que o auditor a reverifica por conta própria?

Garante que `d_i = C1^x_i` usa o mesmo `x_i` de `h_i = g^x_i`, ou seja, `log_g(h_i) = log_C1(d_i)`, sem revelar `x_i`. Sem ela, uma autoridade (ou quem intercepta a parcela) poderia mandar um `d_i` qualquer e deslocar o total. O desafio Fiat-Shamir inclui domínio, eleição, autoridade, candidato, grupo, `h_i`, `C1`, `d_i`, `a1` e `a2`, então uma prova não serve em outro contexto. O auditor reverifica porque não confia no servidor: o coletor poderia ter aceitado parcelas falsas ou publicado um `authority_partials.json` alterado. Ele refaz a verificação a partir do protocolo público, sem importar `src.authorities`, e contra o agregado **recalculado** do quadro, não contra o publicado. O teste `tests/auditor/test_auditor.py::test_auditor_proof_check_matches_partial_decryption_protocol` garante que as duas implementações coincidem.

### 5.5 O que o recibo prova e o que ele não revela?

O recibo assinado é a declaração do servidor, com RSA-PSS e domínio próprio, de que a cédula do eleitor X é o registro de índice `i` com hash `H` do quadro. Com `verify_receipt_in_board`, o eleitor confere a assinatura do servidor, que o registro está no quadro, que é idêntico à cédula que ele enviou e que o quadro está íntegro em relação a um checkpoint. Se o registro sumir ou mudar, o eleitor tem prova assinada. O recibo da eleição (`compute_receipt`) é recalculável a partir do registro. Nenhum dos dois contém o voto em claro nem o `r`; só identificadores, índice e hash. O recibo não prova que o voto é 0/1, nem o resultado, nem ausência de coerção: um eleitor que guardasse o `r` poderia provar o voto a terceiros (o cliente da demo descarta o `r`).

### 5.6 Por que alteração, remoção intermediária e reordenação no quadro são detectadas, e por que a remoção da ÚLTIMA cédula antes da apuração não é?

Cada registro guarda o próprio `index` e o hash do anterior, e seu hash cobre cédula, assinatura, índice e elo. Alterar o conteúdo muda o hash (verificação a); recalcular os hashes é possível, pois a função é pública, mas a assinatura do eleitor falha (c). Remover um registro do meio ou reordenar deixa `index` fora de ordem e um `previous_hash` que não confere (a); depois da apuração, o produto homomórfico também diverge (d). Já a remoção da **última** cédula antes da apuração deixa um prefixo perfeitamente válido: a cadeia só aponta para trás e nada nela fixa o tamanho. Se o servidor apurar o quadro truncado, agregado, parcelas e resultado ficam coerentes, e o auditor vê uma abstenção. Para detectar, o auditor precisaria de um checkpoint (tamanho e hash final) publicado por uma fonte independente do servidor; `verify_board` aceita um checkpoint, mas o auditor atual não recebe um. Hoje só o eleitor afetado percebe: o recibo dele não confere no quadro (cenário 4c da T14).

### 5.7 Por que o auditor não acessa `data/private/` nem importa o servidor?

Porque a auditoria precisa ser feita por qualquer pessoa, só com o que foi publicado. Se importasse o servidor (`src.server`, `src.election` ou `src.authorities`), estaria confiando no código e no estado de quem está sendo auditado, e um defeito ou uma manipulação ali poderia aprovar a si mesma. Se precisasse de chaves privadas, quem audita poderia decifrar votos, e a verificação deixaria de ser pública. O auditor importa somente `src.crypto` e `src.bulletin_board` (primitivas e formato público); o recálculo das cifras do quadro fica em `src/auditor/board_tally.py`, que segue a mesma regra e é reaproveitado pelas autoridades (a dependência é só nesse sentido: as autoridades importam `board_tally`, nunca a classe `Auditor`), abre só os seis arquivos de `public_dir` e confere o resultado sem segredo (`C2 ≡ g^T·∏d_i`). Os testes `test_auditor_imports_only_crypto_and_bulletin_board` e `test_auditor_reads_only_public_files` garantem isso, e ele pode rodar como processo separado: `python -m src.auditor.auditor data/demo/public`.

### 5.8 Prova 0/1: limitação assumida pela equipe

**O que falta.** Por questão de prazo, a equipe não integrou a prova de que cada cifra contém 0 ou 1. O módulo `src/crypto/bit_proof/` existe (prova OR de Chaum-Pedersen: `prove_bit`, `verify_bit_proof`), mas o formato da cédula de `src/crypto/ballots.py` aceita exatamente `schema_version, election_id, voter_id, ciphertexts` e, em cada cifra, `candidate_id, c1, c2`; um campo de prova é rejeitado (`BallotFormatError`). Assim, nem o servidor nem o auditor conseguem verificar que cada cifra é 0 ou 1. O resumo da demo diz isso na segunda `Nota:`.

**Risco.** O cliente honesto usa `encrypt_bit`, que recusa `m ∉ {0, 1}`, mas um eleitor malicioso pode cifrar por conta própria e assinar uma cédula estruturalmente válida: `m = 2` (`g^2`), `m = −1` (`g^−1 = g^(q−1)`, que também está no subgrupo) ou 1 para os dois candidatos. Exemplos com 3 cédulas: `(2, 0)` gera Alice 3, Bob 1 (4 votos para 3 cédulas); `(−1, +2)` gera Alice 0, Bob 3 e ainda "soma 1" como uma cédula honesta; `(1, 1)` gera Alice 2, Bob 2. Em todos esses casos o servidor aceita a cédula e emite recibo, porque não tem como ver o conteúdo das cifras.

**O que o sistema detecta mesmo assim.** Duas verificações, as duas na apuração e no auditor e com o mesmo critério:

1. **Cada total em `[0, nº de cédulas]`.** O limite é o número de cédulas aceitas (o `ballot_count` do agregado na apuração; o número de registros do quadro no auditor), e não o número de eleitores cadastrados: com abstenção, os dois diferem. Se algum total sair do intervalo (ex.: `m = 1000` ou um total negativo), o logaritmo discreto limitado não encontra `T`, a apuração falha com `DecryptionError` sem publicar `result.json`, e o auditor reprova a verificação e).
2. **Soma dos totais = nº de cédulas.** O sistema não tem voto em branco: o enunciado manda cifrar 1 para o escolhido e 0 para os demais, o cliente honesto (`VoterClient.build_ballot`) sempre cifra exatamente um 1 e não há candidato "branco". Quem se abstém não envia cédula. Então cada cédula honesta soma 1, e a soma dos totais tem de ser **igual** ao número de cédulas (por isso igualdade, e não `≤`). Se não for, a apuração lança `InconsistentTotalsError` e não publica; se um servidor desonesto publicar mesmo assim, o auditor reprova com `soma dos totais (4) difere do número de cédulas do quadro (3)`. Isso pega `(2, 0)` (4 votos para 3 cédulas), `(1, 1)` (Alice 2, Bob 2) e uma cédula toda em 0.

**O que a soma NÃO cobre.** A detecção é **agregada**: diz que alguma cédula não soma 1, mas não qual nem de que eleitor, e bloqueia a apuração inteira (negação de serviço por um único eleitor). E não pega cédulas que somam 1 com valores fora de {0, 1}: `(−1, +2)` gera Alice 0, Bob 3, com soma 3 = número de cédulas. Nesse caso o servidor aceita, a apuração publica e o auditor aprova. Só a prova 0/1 por cifra resolve.

**O que seria necessário para corrigir.** (1) Uma prova 0/1 por cifra (`prove_bit`), dentro do corpo **assinado** da cédula, ligada ao contexto (eleição, eleitor, candidato) para não ser copiada; e (2) uma prova de que a soma das cifras da cédula é 1: com `(A, B) = (∏c1, ∏c2) = (g^R, g·h^R)`, uma prova de Chaum-Pedersen de que `log_g(A) = log_h(B/g)`. Isso exige nova versão do formato em `ballots.py`, no registro do quadro, em `Election.submit_ballot` (rejeitar com `InvalidProofError`, já reservado) e na verificação c) do auditor.

**Testes.** Os testes `xfail(strict=True)` da T14 já descrevem o comportamento desejado: `tests/security/test_attacks.py::test_server_should_reject_vote_outside_0_1[2|-1|1000]` (servidor deveria recusar com `InvalidProofError`) e `::test_auditor_should_detect_vote_outside_0_1[m=-1-e-m=2]` (auditor deveria reprovar), além de 16 testes em `auditor/test_auditor.py`, `test_election_voting.py` e `test_server_voting.py` sobre a prova que não trafega (20 `xfailed` no total da suíte). Por serem estritos, quando a prova for integrada eles passam a falhar e obrigam a atualizar os testes e o README. O caso `[m=2]` era `xfail` e virou teste normal: a verificação da soma passou a satisfazê-lo. A detecção da soma está em `test_ballot_not_summing_one_is_detected_by_tally_and_auditor[m=2|1-para-os-dois]`; o limite com abstenção, em `test_abstention_bounds_totals_by_ballots_not_voters`; e o caso que continua passando, em `test_ballot_keeping_sum_one_is_accepted_and_audits_valid`.

### 5.9 Por que a demo exige Linux, macOS ou WSL?

O quadro público serializa leitores e escritores com `fcntl.flock` (bloqueio compartilhado para ler, exclusivo para acrescentar e gravar com `fsync`), e o módulo `fcntl` só existe em sistemas Unix. O `demo.py` testa isso antes de criar qualquer arquivo e sai com código 3 e uma mensagem clara no Windows nativo. No Windows, use o WSL. Na suíte de testes, os testes que dependem do quadro aparecem como `skipped` no Windows nativo, e os do próprio quadro falham.

---

### 5.10 O README cita Diffie-Hellman. Onde ele aparece?

Não há uma implementação separada de Diffie-Hellman (nenhuma troca de chaves entre duas partes); a ideia aparece em três pontos do esquema:

- **Chave de cada autoridade.** Cada autoridade sorteia `x_i` e publica só `h_i = g^x_i mod p` (`Authority.generate` em `src/authorities/authority.py`), mantendo `x_i` secreto em `private/`: é a metade pública de um Diffie-Hellman. A chave da eleição é `h = ∏ h_i = g^(Σ x_i)` (`compute_joint_public_key`), e ninguém conhece `Σ x_i`.
- **ElGamal.** Ao cifrar (`encrypt_bit`), o eleitor sorteia um `r` efêmero e publica `c1 = g^r`, a metade dele. O segredo compartilhado é `h^r = (g^x)^r = (g^r)^x = c1^x`: o eleitor o calcula com `h` e `r`; quem tivesse `x` o calcularia com `c1`. Esse valor mascara a mensagem em `c2 = g^m · h^r`.
- **Apuração.** Como `x` não existe em lugar nenhum, cada autoridade calcula a sua parte do segredo compartilhado da cifra agregada, `d_i = C1^x_i`, e `∏ d_i = C1^(Σ x_i) = h^R`.

O sigilo depende da hipótese de Diffie-Hellman decisional (DDH) no subgrupo de ordem `q` do grupo RFC 3526: vendo `g^x` e `g^r`, ninguém distingue `g^(x·r)` de um elemento aleatório (pergunta 5.2). Por isso o grupo tem `q` primo e o código confere que `h_i`, `c1` e `c2` estão nesse subgrupo.

### 5.11 Um servidor malicioso consegue descobrir o voto de um eleitor fazendo as autoridades decifrarem uma única cédula?

**O ataque.** A parcela `d_i = C1^x_i` funciona para qualquer cifra, não só para o agregado. Se o servidor enviasse às autoridades a cifra de uma única cédula como se fosse o agregado, a decifração conjunta devolveria 0 ou 1 e o voto daquele eleitor vazaria, inclusive sem nada ser publicado (o auditor não veria).

**O que é garantido.** Antes de usar `x_i`, cada autoridade (`compute_authority_partials`, com `board_path` obrigatório) lê o quadro público e só decifra o produto de **todas** as cédulas válidas, assinadas e únicas **do quadro que ela lê**:

- cadeia íntegra: índices, elos e hashes (`hash_chain.verify_board`);
- cada cédula assinada com a chave cadastrada do eleitor em `election.json`, eleitor cadastrado e no máximo uma cédula por eleitor;
- cifras no subgrupo e nenhum `c1` repetido (`src/auditor/board_tally.py`, o mesmo código do auditor);
- `C1` e `C2` de cada candidato, o conjunto de candidatos e o `ballot_count` iguais aos recalculados do quadro.

Qualquer diferença gera `AggregateVerificationError` e nenhuma parcela é produzida. A etapa 7 mostra a recusa. As assinaturas são indispensáveis: `hash_record` e `genesis_hash` são públicos, então, sem elas, o servidor montaria um quadro "válido" com a cédula do alvo mais cédulas de valor conhecido e descobriria o voto por subtração. Os testes estão no cenário 8 da T14 (`tests/security/test_attacks.py`).

**O que continua aberto.** A autoridade confia nos arquivos que lê: o quadro e `election.json`. Um servidor que controle esses arquivos pode apresentar a ela:

- um **quadro alternativo**, por exemplo só com a cédula genuína de um eleitor e a cadeia recalculada. Cadeia, assinatura e produto conferem, `ballot_count` = 1, e o voto vaza (`test_alternative_board_is_accepted_without_independent_checkpoint`, uma limitação assumida);
- um **`election.json` alternativo**, por exemplo com chaves de eleitores trocadas por chaves do servidor, o que deixaria o servidor assinar cédulas forjadas.

Isso só se resolve com um checkpoint do quadro (tamanho e hash final) vindo de uma fonte independente do servidor, passado em `expected_checkpoint`, que é a mesma exigência da remoção da última cédula (pergunta 5.6), e com `election.json` obtido de fonte confiável. `test_alternative_board_is_refused_with_independent_checkpoint` mostra a recusa quando há checkpoint. Hoje o sistema não publica um checkpoint independente, e a demo não passa um. Além disso, numa eleição com uma única cédula, o próprio resultado revela o voto. Portanto **não há proteção total**: a conferência impede que as autoridades decifrem algo diferente do produto do quadro que leem, mas não impede que o servidor troque o próprio quadro ou o cadastro.

**Código compartilhado com o auditor.** A leitura das cifras do quadro, a checagem de subgrupo e de `c1` repetido e o produto homomórfico por candidato estão em um só lugar, `src/auditor/board_tally.py`, usado pelo auditor, pela apuração (`build_aggregate`) e pela conferência das autoridades. A independência do auditor é de **dados** (lê só os arquivos públicos, nunca `data/private/` nem o estado do servidor) e de **servidor** (não importa `src.server`, `src.election` nem `src.authorities`); **não** é independência de implementação. Um defeito nesse código afetaria a apuração e o auditor da mesma forma, e o auditor não o perceberia. A verificação das provas de Chaum-Pedersen continua reimplementada no auditor (pergunta 5.4).

### 5.12 Eleitores coniventes conseguem descobrir o voto de alguém copiando a cédula dele?

Sim, e esta é uma **limitação de sigilo** assumida: o ataque de cópia de cédula descrito por Cortier e Smyth contra o Helios.

**Como funciona.** A cédula de V está no quadro público. Um eleitor conivente copia as cifras de V e as **re-randomiza**: multiplica cada uma por uma cifra de 0, `(g^s, h^s)`. O `c1` muda, então a regra de `c1` repetido (servidor, autoridades e auditor) não pega a cópia, mas a cifra continua cifrando o mesmo voto de V. O conivente assina com a própria chave, e por isso a assinatura é válida. O servidor aceita, as autoridades decifram (o quadro confere) e o auditor aprova.

**O efeito.** Cada cópia soma ao resultado mais uma vez o voto de V, então o resultado se desloca na direção do voto de V. Com eleitores coniventes copiando a cédula de V, comparar os totais com e sem as cópias revela o voto. A cópia **exata** (mesmo `c1`) é recusada no recebimento; a re-randomizada, não.

**O que seria necessário para corrigir.** Uma prova de conhecimento por cifra (de que quem envia conhece `r` e `m`) **ligada à identidade do eleitor**, por exemplo com o `voter_id` no desafio Fiat-Shamir. Assim, uma cópia não teria prova válida para outro eleitor. O formato da cédula não transporta essa prova, que é a mesma lacuna da prova 0/1 (pergunta 5.8).

**Teste.** `tests/security/test_attacks.py::test_rerandomized_copy_of_another_voters_ballot_is_accepted` (cenário 9 da T14, LIMITAÇÃO ASSUMIDA): sem a cópia o resultado seria Alice 1 x 1 Bob; com ela, Alice 2 x 1 Bob e auditoria válida.

## 6. Plano B para falhas ao vivo

1. **Executar novamente.** `python demo.py --pause`. Cada execução apaga e recria `data/demo/` (o marcador `.urna_demo` permite isso com segurança) e gera chaves novas; o cenário e os totais são os mesmos. Ctrl+C (ou Ctrl+D numa pausa) encerra o demo com `Demonstração interrompida pelo usuário` e código 130, sem traceback; é só rodar de novo. Se o demo parar com `ERRO: a etapa N divergiu do esperado: …` (código 1), leia o motivo na linha `ERRO:` da etapa e rode de novo; se repetir, vá para o item 3.
2. **Rodar via WSL** (se o computador for Windows e aparecer o erro do `fcntl`, código 3). No PowerShell, na pasta do projeto: `wsl -- python3 demo.py --pause` (o WSL precisa ter `python3` e `cryptography` instalados; veja a seção 1). Se houver problema com a pasta do Windows montada em `/mnt/c`, rode dentro do WSL com a saída no sistema de arquivos Linux: `python3 demo.py --pause --output-dir ~/urna-demo`. Instale e teste isso **antes** do dia da apresentação.
3. **Mostrar a saída de referência salva.** Abra [`docs/demo_output_exemplo.txt`](demo_output_exemplo.txt) (por exemplo, `cat docs/demo_output_exemplo.txt` ou no editor) e siga o mesmo roteiro da seção 4: as linhas citadas aqui são dessa execução. Avise que os números hexadecimais mudam a cada execução.
4. **Complemento opcional**, se sobrar tempo ou a banca pedir o auditor isolado: depois de uma execução bem-sucedida, `python -m src.auditor.auditor data/demo/public` (válida, saída 0) e `python -m src.auditor.auditor data/demo/tampered_public` (inválida, saída 1).
5. **Terminal sem ✔/✘/→.** O demo troca caracteres que o console não consegue mostrar por `?`, em vez de quebrar; a lógica e os códigos de saída não mudam.
