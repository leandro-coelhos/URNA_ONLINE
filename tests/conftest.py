"""Fixtures compartilhados: a eleição completa de ``tests/support/election_scenario.py``.

Promovidos de ``tests/auditor/test_auditor.py`` para que a suíte de segurança
(``tests/security/``) use o mesmo cenário. Todo dado é gravado em diretórios
temporários do pytest (``tmp_path``/``tmp_path_factory``); nenhum teste lê ou
escreve em ``data/`` do repositório.

Nenhum módulo é substituído em ``sys.modules``: o cenário usa os módulos
reais de ``src.crypto`` e ``src.bulletin_board``.

O fixture de sessão ``scenario`` é montado uma vez e compartilhado: os testes
devem alterar apenas cópias (``public_copy``), nunca ``scenario.public_dir``
nem os objetos vivos (``scenario.election``…). Não há mais ``proof_scenario``:
o formato da cédula não transporta prova 0/1 (ver os ``xfail`` estritos em
``tests/auditor/test_auditor.py``).
"""

import shutil

import pytest

# O cenário usa o BulletinBoard real (fcntl: Linux/macOS/WSL). Ele é importado
# só dentro dos fixtures, para que os testes que não usam o quadro continuem
# rodando em qualquer sistema.
_NO_FCNTL = "src.bulletin_board.board usa fcntl: o quadro público real exige Linux, macOS ou WSL"


def pytest_configure(config):
    # O registro oficial do marker está em pyproject.toml. Repetido aqui para
    # não gerar PytestUnknownMarkWarning se o pytest for chamado de fora da
    # raiz do projeto (onde o pyproject.toml não é encontrado).
    config.addinivalue_line(
        "markers",
        "security: suíte de segurança e adulteração da T14 (python -m pytest -q -m security)",
    )


@pytest.fixture(scope="session")
def rsa_keys():
    pytest.importorskip("fcntl", reason=_NO_FCNTL)
    from tests.support.election_scenario import VOTES, _new_rsa_key

    # RSA de 2048 bits é lento: 3 eleitores + 1 intruso para a sessão toda.
    return [_new_rsa_key() for _ in range(len(VOTES) + 1)]


@pytest.fixture(scope="session")
def scenario(tmp_path_factory, rsa_keys):
    from tests.support.election_scenario import build_election

    return build_election(tmp_path_factory.mktemp("eleicao"), rsa_keys)


@pytest.fixture
def public_copy(scenario, tmp_path):
    """Cópia só de data/public/: data/private/ nem existe ao lado dela."""
    destination = tmp_path / "publico"
    shutil.copytree(scenario.public_dir, destination)
    return destination
