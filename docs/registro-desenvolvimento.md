# Registro de desenvolvimento para o relatório técnico

## Finalidade e acordos

Este documento registra a contribuição de Carlos e o trabalho realizado com
auxílio de IA, para apoiar o relatório do grupo e a preparação para a arguição.
Não é o relatório final nem comprova, sozinho, compreensão dos integrantes.

- A documentação desta contribuição fica em `docs/`. Não alterar o `README.md`
  do repositório sem uma nova orientação explícita do usuário.
- A branch de trabalho é `feat/cadastro-assinaturas-quadro-recibos`.
- O escopo previsto são as issues #4 (cadastro), #7 (assinaturas), #8 (quadro
  público) e #6 (recibos). Até este registro, apenas o núcleo da #4 foi implementado.
- Registrar o que foi realmente implementado e testado, distinguindo propostas,
  dependências e verificações ainda pendentes.
- Acrescentar entradas datadas a cada etapa relevante; se uma decisão mudar,
  registrar a mudança e seu motivo, preservando o histórico anterior.
- Aprendizados e dificuldades pessoais devem ser descritos pelos integrantes
  a partir da experiência real; não inferir que alguém já domina um conceito.

## Requisitos do relatório no enunciado

O relatório técnico vale 3 pontos, tem **máximo de 10 páginas para o grupo**
e deve ser entregue com os demais arquivos até **23/11/2026**, no Aprender3.
O uso de IA está condicionado à compreensão e à capacidade de explicar cada
trecho produzido. O texto final deve refletir o código e o entendimento do grupo.

Conteúdo obrigatório a consolidar ao final:

| Tema exigido | Evidências que devemos reunir |
|---|---|
| Arquitetura e responsabilidades das entidades | Módulos reais, interfaces e fluxo integrado |
| Modelo de ameaças | Adversários considerados, capacidades e hipóteses de confiança |
| Cifragem e apuração sem decifrar votos individuais | Fórmulas, implementação e exemplos de agregação |
| Chave conjunta e decifração pelas autoridades | Geração, contribuições e validação das participações |
| Integridade do quadro público e autenticação | Cadeia de hashes, assinaturas e proteção do cadastro |
| Auditoria e verificação individual | Dados públicos usados e procedimento de conferência do recibo |
| Parâmetros e algoritmos com justificativas | Grupo, tamanhos das chaves, função hash e referências |
| Atendimento dos requisitos e limitações | Argumentos, hipóteses e testes de ataques |
| Dificuldades e aprendizados | Relatos reais dos integrantes |

A análise de segurança deve abordar explicitamente os quatro casos do enunciado:

1. Eleitor cifra um valor diferente de 0 ou 1.
2. Todas as autoridades conspiram.
3. Uma autoridade não participa da apuração.
4. O recibo permite, ou não, provar a terceiros em quem o eleitor votou.

Esses itens continuam pendentes de consolidação. Os documentos de trabalho
podem ser maiores; o relatório final deverá selecionar e sintetizar o material
para respeitar o limite total de páginas.

## 19/11/2026 — Implementação inicial do cadastro (#4 / T05)

**Objetivo:** associar eleitores e autoridades às suas chaves públicas antes da
votação, rejeitando dados inválidos, duplicatas e inclusões fora da etapa permitida.

**Arquivos envolvidos:**

- [Implementação](../src/server/registration.py) e inicialização dos pacotes `src` e `src/server`.
- [Testes](../tests/test_registration.py) e inicialização do pacote `tests`.
- [Guia técnico e contrato de integração](cadastro.md).
- [Dependência RSA](../requirements.txt): `cryptography==49.0.0`.
- [Regras de arquivos ignorados](../.gitignore): chaves, dados privados e artefatos locais.

**Comportamento implementado:**

- Cadastro e consulta de eleitores e autoridades em memória, por eleição.
- Validação de identificadores e de chaves públicas RSA dos eleitores.
- Validação da chave ElGamal individual da autoridade no subgrupo fornecido.
- Rejeição de identificador ou chave repetida dentro do mesmo papel.
- Consulta da etapa atual antes de incluir e congelamento explícito com `freeze()`.
- Exportação de uma cópia dos dados públicos compatível com JSON.

**Decisões e justificativas:**

| Decisão | Motivo |
|---|---|
| Receber somente chaves públicas | A geração e a guarda de segredos pertencem aos participantes |
| Normalizar RSA para PEM/SPKI | Detectar a mesma chave mesmo quando recebida em formatos diferentes |
| Consultar a etapa por uma função fornecida pelo controlador | Permitir desenvolvimento e testes sem implementar o ciclo eleitoral do colega |
| Receber p e q previamente validados | Manter a seleção e validação do grupo sob responsabilidade do módulo criptográfico |
| Exportar h_i como string decimal | Preservar inteiros grandes em leitores JSON com precisão numérica limitada |
| Usar registros imutáveis e exportar cópias | Evitar que consultas alterem acidentalmente o cadastro interno |

As regras detalhadas, incluindo tamanhos RSA, expoente e formato dos
identificadores, estão no [guia de cadastro](cadastro.md#regras-de-validação).
São decisões desta implementação; não representam aprovação já obtida do grupo.

**Verificação realizada:**

- Ambiente observado: Python 3.13.2 e `cryptography` 49.0.0.
- Comando executado: `python3 -m unittest discover -s tests -v`.
- Resultado: **22 testes passaram** na execução inicial, antes deste ajuste documental.
- Cobertura de cenários: cadastros válidos, três autoridades, duplicatas,
  PEM malformado ou ambíguo, chave privada enviada por engano, chave de outro
  algoritmo, RSA pequeno ou fora da política, chave fora do subgrupo, etapas
  proibidas, congelamento, consultas e exportação sem campos privados.
- Os testes usam chaves RSA temporárias em memória e o grupo 14 da RFC 3526.
  Esse grupo é uma fixture; a escolha do grupo da eleição permanece com o módulo
  criptográfico. Expoentes pequenos nos exemplos de teste não são geração segura.
- A instalação em um ambiente virtual novo e outras versões de Python não
  foram verificadas nesta etapa.

**Limitações e integração pendente:**

- O cadastro não persiste nem restaura arquivos; o bloqueio deve sobreviver à
  reinicialização quando a persistência for integrada.
- O controlador deve chamar `freeze()` ao abrir a votação e impedir retrocessos.
- O módulo pressupõe p e q primos previamente validados; não testa primalidade.
- Validar uma chave não comprova identidade nem posse da chave privada.
- A lista pública ainda precisa ser autenticada e preservada contra substituição
  por um administrador malicioso. A exportação e o campo `frozen` não bastam.
- Não há suporte a operações concorrentes nesta etapa.
- Persistência, CLI e módulos reais dos colegas ainda não foram integrados.

**Relação com o relatório:** esta etapa fornece material para arquitetura,
cadastro/autenticação, parâmetros de validação e limitações da elegibilidade.
Os testes isolados não demonstram segurança de uma eleição completa.

**Pontos para estudo e relato posterior do integrante:** distinguir cadastro de
geração de chaves, validação de chave de prova de posse, duplicidade de cadastro
de duplicidade de voto, e congelamento em memória de proteção contra adulteração.
Registrar quais desses conceitos foram difíceis e como foram compreendidos
após a leitura e execução; ainda não há um relato pessoal validado.

## 19/11/2026 — Organização da documentação

Por solicitação de Carlos, as alterações feitas anteriormente no `README.md`
foram retiradas. As instruções de instalação e execução dos testes foram movidas
para `docs/cadastro.md`, e este registro foi criado para apoiar o relatório.
Não houve mudança no código do cadastro nesta etapa documental.

## 19/11/2026 — Revisão e conclusão local do módulo da #4

**Escopo da conclusão:** os cinco critérios da issue #4 estão implementados
no módulo de cadastro e verificados isoladamente. Isso não significa que o
servidor completo esteja pronto nem que a integração com os colegas tenha sido
executada. A persistência não é um critério explícito da #4; permanece uma
necessidade da arquitetura cujo formato e responsável precisam ser combinados.

**Alterações desta revisão:**

- Acrescentada ao [guia de cadastro](cadastro.md#entrega-da-issue-4-e-critérios-de-aceitação)
  uma tabela que relaciona os cinco critérios à implementação e aos testes.
- Acrescentado um teste com três eleitores e três autoridades que verifica
  inscrições, congelamento, rejeições nas etapas seguintes e consultas aos dados.
- Acrescentado um teste da passagem de CONFIGURACAO para CADASTRO: rejeitar uma
  inscrição antecipada não pode impedir uma inscrição posterior na etapa correta.
- Acrescentado um teste de falha do provedor de estado: a inscrição falha e os
  dados permanecem intactos quando não é possível consultar a etapa da eleição.
- Documentado como executar individualmente o cenário de três participantes
  de cada papel. Não foi necessário alterar a lógica de produção nesta revisão.

**Verificação realizada:** `python3 -m unittest discover -s tests -v`, com
Python 3.13.2 e `cryptography` 49.0.0: **25 testes passaram**. O README permaneceu
sem diferenças em relação ao commit atual, verificado com
`git diff --exit-code -- README.md`.

**Entrega local:** alterações na branch `feat/cadastro-assinaturas-quadro-recibos`,
sem commit, push, mudança de estado da issue no GitHub ou início da #7 nesta
etapa, conforme a orientação de concluir a #4 antes da publicação.

**Contrato ainda a integrar:** obter a etapa atual da #5, receber p e q validados
pela #9, chamar `freeze()` antes da abertura e definir a persistência/autenticação
do cadastro público com o grupo. Essas dependências não foram transferidas para
o escopo da #4 nem consideradas já resolvidas pelos testes isolados.

## Modelo para as próximas entradas

Ao concluir uma etapa relevante, acrescentar:

- Data e issue relacionada.
- Objetivo e arquivos envolvidos.
- Comportamento implementado.
- Decisões tomadas e justificativas; indicar o que ainda depende do grupo.
- Comandos realmente executados, resultados e ambiente relevante.
- Limitações, integrações e testes pendentes.
- Dificuldades reais e aprendizados relatados pelo integrante.
- Relação com as seções do relatório e referências consultadas.
