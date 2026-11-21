"""Parâmetros públicos do grupo MODP 14, definido no RFC 3526."""

from dataclasses import dataclass


# O RFC apresenta o primo separado em blocos de oito dígitos hexadecimais.
# Removemos os espaços para manter uma representação única no programa.
RFC3526_GROUP14_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C"
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6"
    "955817183995497CEA956AE515D2261898FA051015728E5A"
    "8AACAA68FFFFFFFFFFFFFFFF"
)


@dataclass(frozen=True)
class GroupParameters:
    """Parâmetros públicos usados nas operações modulares."""

    p: int
    q: int
    g: int
    name: str = "custom"


def rfc3526_group14() -> GroupParameters:
    """Retorna o grupo público de 2048 bits usado neste projeto.

    O RFC fornece p e g. Para este grupo MODP, q é calculado como (p - 1) / 2
    e validado durante a inicialização do módulo.
    """

    p = int(RFC3526_GROUP14_P_HEX, 16)
    q = (p - 1) // 2
    return GroupParameters(p=p, q=q, g=2, name="RFC3526-MODP-14")


DEFAULT_PARAMETERS = rfc3526_group14()


