from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn


Params = tuple[EcGroup, Bn, EcPt, EcPt]
BnDict = dict[str, Bn]
EcPtDict = dict[str, EcPt]
Mac = tuple[EcPt, EcPt]


def setup() -> Params:
    """ generate all public parameters """
    G = EcGroup(714)
    g = G.generator()
    h = G.hash_to_point(b'h')
    return (G, G.order(), g, h)


def keygen(params: Params) -> tuple[Bn, EcPtDict]:
    (_, p, _, h) = params
    sk_names = ['x0', 'x1']
    sk = {name: p.random() for name in sk_names}
    iparams = {name.upper(): sk[name]*h for name in sk_names[1:]}
    return sk, iparams


def mac(params: Params, sk: BnDict, m: Bn) -> Mac:
    """ compute mac GGM """
    (G, _, _, _) = params
    u = G.hash_to_point(b"u")
    hx = sk['x0'] + sk['x1'] * m
    u_prime = hx * u
    sigma = (u, u_prime)
    return sigma


def verify(params: Params, sk: BnDict, m: Bn, sigma: Mac) -> bool:
    """ verify mac DDH """
    assert len(sk) > 0 and m
    (G, _, _, _) = params
    (u, u_prime) = sigma
    hx = sk['x0'] + sk['x1'] * m
    return u != G.infinite() and u_prime == hx * u
