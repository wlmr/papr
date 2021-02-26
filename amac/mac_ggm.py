from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn


Params = tuple[EcGroup, Bn, EcPt, EcPt]
BnDict = dict[str, Bn]
EcPtDict = dict[str, EcPt]
Mac = tuple[EcPt, EcPt]


# TODO: make k control which group is generated


def setup(k: int) -> Params:
    """ generate all public parameters """
    G = EcGroup()
    g = G.hash_to_point(b'g')
    h = G.hash_to_point(b'h')
    return (G, G.order(), g, h)


def keygen(params: Params) -> tuple[Bn, EcPtDict]:
    (_, p, _, h) = params
    sk_names = ['x0', 'x1']
    sk = {name: p.random() for name in sk_names}
    iparams = {name.upper(): sk[name]*h for name in sk_names[1:]}
    return sk, iparams


def mac(params: Params, sk: BnDict, m: bytes) -> Mac:
    """ compute mac GGM """
    # assert len(sk) > 0 and m
    (G, _, _, _) = params
    u = G.hash_to_point(b"u")
    em = Bn.from_binary(m)
    hx = sk['x0'] + sk['x1'] * em
    u_prime = hx * u
    sigma = (u, u_prime)
    return sigma


def verify(params: Params, sk: BnDict, m: bytes, sigma: Mac) -> bool:
    """ verify mac DDH """
    assert len(sk) > 0 and m
    (G, _, _, _) = params
    (u, u_prime) = sigma
    em = Bn.from_binary(m)
    hx = sk['x0'] + sk['x1'] * em
    return u != G.infinite() and u_prime == hx * u


if __name__ == "__main__":
    params = setup(500)
    m = b'my secret identity'
    n = len(m)
    (sk, _) = keygen(params, 1)
    sigma = mac(params, sk, m)
    assert verify(params, sk, m, sigma)
