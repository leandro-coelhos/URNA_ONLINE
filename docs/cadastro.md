# Cadastro de eleitores e autoridades — issue #4 (T05)

## Objetivo e limite desta entrega

O cadastro associa uma identificação a uma chave pública antes da votação.
O módulo `src/server/registration.py` implementa esse serviço em memória,
com consultas e exportação pública. Ele não gera chaves, não recebe votos e
não abre a votação. O código usa `cryptography` somente para ler, verificar
tipo/parâmetros e normalizar chaves RSA; não utiliza uma biblioteca de ElGamal.

Os candidatos pertencem à configuração da eleição, prevista em
`src/election/candidates.py`. Um candidato que também vota terá cadastro
de eleitor. Ser candidato, por si só, não exige um par de chaves.

## Entrega da issue #4 e critérios de aceitação

O escopo desta entrega é o **módulo de cadastro**, conforme os cinco critérios
da issue #4. A validação é feita por testes locais com parâmetros de um grupo
padronizado e uma função controlada pelos testes que informa a etapa da eleição.
Isso permite desenvolver o cadastro sem depender da implementação dos colegas.

| Critério da issue | Implementação | Evidências em `tests/test_registration.py` |
|---|---|---|
| Cadastrar identificador e chave pública RSA do eleitor | `register_voter` e `get_voter` | `test_register_and_query_voter`, `test_accept_text_pem` |
| Cadastrar autoridades eleitorais | `register_authority` e `get_authority` | `test_register_three_authorities` |
| Rejeitar eleitores e autoridades duplicados | Verificação de identificador e de chave dentro de cada papel | `test_duplicate_voter_id_does_not_replace_key`, `test_duplicate_authority_id_and_key`, `test_same_rsa_key_in_another_format_is_still_duplicate` |
| Rejeitar chaves públicas inválidas | Validação RSA e pertencimento ao subgrupo de ElGamal, com parâmetros previamente validados | Testes `test_reject_*` para chaves privadas, malformadas, de outro algoritmo, RSA fora da política e autoridades fora do subgrupo |
| Impedir cadastros após o início da votação | Consulta da etapa em cada inclusão e bloqueio com `freeze()` | `test_reject_registration_outside_registration_phase`, `test_state_provider_is_consulted_again`, `test_freeze_is_irreversible_and_preserves_queries` |

O cenário `test_complete_registration_flow` cadastra três eleitores e três
autoridades, congela o cadastro e verifica que novas inscrições são recusadas
durante e depois da votação, preservando consultas e dados. Ele não executa
uma eleição completa: não há envio de votos, apuração ou auditoria nesse teste.

Persistência em arquivos não aparece explicitamente nos critérios da #4.
Ela continua necessária para o armazenamento planejado no README, mas sua
distribuição entre os integrantes e o formato final dos arquivos precisam ser
combinados. Não foi adicionada silenciosamente a esta entrega. A integração
real com o ciclo eleitoral (#5) e o grupo criptográfico (#9) também deve ser
testada quando esses módulos estiverem disponíveis.

Essas pendências da aplicação não significam que a #4 deva implementar os
módulos dos colegas. A revisão desta entrega deve verificar o cadastro e seu
contrato; os testes da eleição completa verificarão a integração posteriormente.

## Instalação e execução dos testes

Use Python 3.11 ou superior. Na raiz do repositório:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Os testes usam `unittest`, incluído no Python, e geram chaves temporárias em
memória. Não é necessário baixar o código dos outros módulos nem fornecer
chaves privadas. A eleição completa ainda não está implementada.

Para acompanhar apenas o cenário de cadastro com três eleitores e três autoridades:

```bash
python -m unittest tests.test_registration.RegistrationTests.test_complete_registration_flow -v
```

O histórico de decisões, verificações e pendências está no
[registro de desenvolvimento](registro-desenvolvimento.md). Este guia descreve
o funcionamento atual; o registro preserva a evolução para apoiar o relatório.

## Como estudar o código

1. `Voter` e `Authority` descrevem os dados públicos de cada participante.
2. `_validate_identifier` estabelece identificadores sem espaços ou acentos.
3. `_normalize_rsa_public_key` lê e padroniza a chave RSA do eleitor.
4. `register_voter` e `register_authority` validam e só depois armazenam.
5. `_require_registration_phase` consulta a etapa; `freeze` fecha o cadastro.
6. `get_voter`, `get_authority` e `export_public_data` permitem consultar os dados.

Na implementação da #7, a lógica RSA foi extraída para `src/crypto/keys.py`.
`_normalize_rsa_public_key` continua no cadastro como adaptador, preservando
`InvalidPublicKeyError` e a interface da #4. Isso permite ao servidor e ao auditor
compartilhar a mesma política sem o auditor importar o módulo de cadastro.

`dataclass(frozen=True)` impede alterações acidentais nos registros devolvidos.
Isso não impede um administrador malicioso de modificar memória, arquivos ou
o código do programa: é uma proteção de programação, não uma prova criptográfica.

## Contrato proposto para integrar os módulos

Esta interface está implementada nesta branch e precisa ser alinhada com o grupo.
Ela evita depender de arquivos dos colegas que ainda não existem.

| Operação | Entrada | Resultado |
|---|---|---|
| `Registration(...)` | `election_id`, `p`, `q`, `state_provider` | Cadastro vazio de uma eleição |
| `register_voter(...)` | `voter_id`, `public_key_pem` (texto ou bytes) | Registro `Voter` |
| `register_authority(...)` | `authority_id`, `public_key` (`h_i`, inteiro) | Registro `Authority` |
| `get_voter(...)` | Identificador | `Voter`; `KeyError` se não existe |
| `get_authority(...)` | Identificador | `Authority`; `KeyError` se não existe |
| `freeze()` | Nenhuma | Bloqueio definitivo de inclusões nesta instância |
| `export_public_data()` | Nenhuma | Cópia de dados públicos compatível com JSON |

Exemplo de integração, quando o módulo de eleição estiver disponível:

```python
from src.server.registration import Registration

# election e group representam objetos fornecidos pela configuração da eleição.
# group.p e group.q precisam ter sido validados pelo módulo criptográfico.
cadastro = Registration(
    election_id="eleicao_2026",
    p=group.p,
    q=group.q,
    state_provider=lambda: election.state,  # Deve retornar o texto "CADASTRO" etc.
)
cadastro.register_voter("eleitor_001", chave_publica_rsa_em_pem)
cadastro.register_authority("autoridade_1", chave_publica_elgamal)
```

Se a eleição representar estados com um `Enum`, o adaptador pode precisar retornar
`election.state.value` ou `.name`, conforme a definição adotada. O participante
não escolhe a etapa; o provedor deve consultar o estado controlado pelo servidor.
Se esse provedor falhar, a exceção é propagada e nenhum participante é incluído;
o chamador deve tratar a falha, sem presumir que o cadastro esteja aberto.

Antes de abrir a votação, o controlador deve validar as condições da eleição
(incluindo pelo menos três autoridades), chamar `freeze()` e preservar/publicar
o cadastro fechado. O método `freeze` não implementa a transição nem verifica o
número de autoridades, responsabilidades das issues #5 e #2. Uma tentativa de
cadastro em etapa posterior também congela esta instância. Só consultar a etapa
em tentativas de cadastro não substitui a chamada explícita de `freeze()`.

O cadastro não contém `has_voted`: impedir voto duplicado pertence ao recebimento
de votos, não à criação da lista de eleitores.

## Regras de validação

- Identificadores: 1 a 64 caracteres ASCII, começando por letra ou número;
  demais caracteres podem incluir `_` e `-`. Maiúsculas e minúsculas são distintas.
  Não use nomes pessoais como identificadores; prefira `eleitor_001`.
- Eleitores: exatamente um bloco PEM público RSA, módulo de 2048 a 8192 bits,
  expoente 65537, módulo ímpar e coprimo com o expoente. O limite superior reduz
  entradas excessivamente grandes; não é uma exigência do enunciado.
- A chave aceita é normalizada para PEM `SubjectPublicKeyInfo` (SPKI). Assim,
  apresentar a mesma chave em PKCS#1 não evita a detecção de duplicatas.
- Autoridades: `h_i` precisa ser um inteiro, `1 < h_i < p - 1`, com
  `pow(h_i, q, p) == 1`. O teste verifica pertencimento ao subgrupo de ordem q;
  excluir 1 evita aceitar a identidade como chave pública.
- `p` e `q` devem vir de um grupo confiável previamente validado, com p de pelo
  menos 2048 bits e q primo de pelo menos 224 bits. O construtor checa coerência
  básica e que q divide p−1, mas NÃO testa primalidade. Validar o grupo é a #9.
- Não há substituição de registros: repetir identificador ou chave no mesmo
  papel é erro. Uma pessoa pode ser eleitor e autoridade, com chaves diferentes
  para funções diferentes. Chaves iguais entre autoridades não são aceitas.
- Inclusões só são aceitas em `CADASTRO`; depois de `freeze()` não há reabertura.

As exceções derivam de `RegistrationError`: `InvalidIdentifierError`,
`InvalidPublicKeyError`, `DuplicateParticipantError` e `RegistrationClosedError`.
Uma falha de cadastro deixa os participantes já registrados intactos.

## Dados públicos e persistência

A exportação tem os campos `schema_version`, `election_id`, `frozen`, `voters`
e `authorities`. Cada eleitor contém `voter_id` e `public_key_pem`. Cada autoridade
contém `authority_id` e `public_key`. Na exportação, a chave ElGamal é uma string
decimal: leitores JSON podem perder precisão ao tratar inteiros muito grandes.

A exportação preserva a ordem de inserção; não é ainda a serialização canônica
das cédulas, que será definida na #7. Não inclui timestamps ou segredos.

O módulo não grava nem restaura arquivos automaticamente. O serviço de
persistência/CLI deverá distribuir esses dados entre `voters.json` e os dados
públicos de autoridades na configuração da eleição. O estado de fechamento
precisará ser preservado ao reiniciar o servidor. Não se deve reconstruir um
cadastro aberto a partir de uma eleição cuja votação já começou. Não existe
suporte a acessos concorrentes nesta etapa: o controlador deve serializar as
operações de cadastro e a transição para votação.

## Limitações e segurança a integrar

Validar formato e parâmetros RSA não prova que o módulo seja produto de dois
primos corretamente escolhidos, nem demonstra posse da chave privada. Validar
`h_i` no subgrupo também não comprova conhecimento de `x_i`. O protocolo das
autoridades deve tratar prova de posse/conhecimento para evitar chaves escolhidas
maliciosamente em função das outras chaves públicas.

O cadastro pressupõe que o processo de inscrição já autorizou a identidade e
associou corretamente sua chave. Rejeitar identificadores/chaves repetidos não
impede uma pessoa de tentar se inscrever com várias identidades e novas chaves.
Essa autorização é uma decisão do modelo de ameaças e da etapa de inscrição.

O objeto e a exportação não autenticam a lista contra um administrador malicioso.
O grupo precisa definir como o cadastro fechado será autenticado e preservado
fora do controle exclusivo do servidor para que o auditor detecte substituições.
O campo `frozen` em JSON, isoladamente, não é evidência de segurança. Portanto,
esta entrega não garante sozinha a elegibilidade de ponta a ponta da eleição.

## Evidências para o relatório

A implementação separa cadastro e geração de chaves, mantém somente dados
públicos e condiciona inclusões à etapa de cadastro. Os testes verificam entradas
válidas e inválidas, duplicatas, bloqueio de inclusões, isolamento de eleições
e exportação sem campos privados. A normalização RSA impede que representações
diferentes da mesma chave contornem a regra de duplicidade.

O grupo ainda deve integrar persistência, ciclo eleitoral, autorização de
identidades, autenticação da lista pública e o protocolo das autoridades.
Registrem dificuldades e aprendizados reais durante essa integração; este
documento não substitui o entendimento nem o relato pessoal dos integrantes.

## Referências

- [Documentação de serialização de chaves](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/).
- [Documentação RSA: parâmetros e formato público](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/).
- [RFC 3526, seção 3](https://www.rfc-editor.org/rfc/rfc3526#section-3): grupo 14 usado apenas nos testes, sem fixar a escolha do grupo da eleição.
