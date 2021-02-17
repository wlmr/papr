from petlib.ec import EcGroup
from petlib.bn import Bn

def setup(k):
    """ generate all public parameters """
    G = EcGroup()
    g = G.hash_to_point(b"g")
    h = G.hash_to_point(b"h")
    return (G, G.order(), g, h)


def keygen(params, n):
    """ mac DDH keygen """
    assert n > 0
    (_, p, _, h) = params
    sk_names = ['x0','x1','y0','y1','z']
    sk = {name:p.random() for name in sk_names}
    iparams = {name.upper():sk[name]*h for name in sk_names[:-1]}
    return (sk, iparams)


def mac(params, sk, m):
    """ compute mac GGM """
    assert len(sk) > 0 and m
    (_, p, g, _) = params
    r = p.random() 
    em = Bn.from_binary(m)
    Hx = sk['x0'] + sk['x1'] * em
    Hy = sk['y0'] + sk['y1'] * em
    sigma_w = r * g
    sigma_x = r * Hx * g
    sigma_y = r * Hy * g
    sigma_z = r * sk['z'] * g
    sigma = (sigma_w, sigma_x, sigma_y, sigma_z) 
    return sigma


def verify(params, sk, m, sigma):
    """ verify mac DDH """
    assert len(sk) > 0 and m
    (sigma_w, sigma_x, sigma_y, sigma_z) = sigma
    em = Bn.from_binary(m)
    Hx = sk['x0'] + sk['x1'] * em   #x0 + x1*m
    Hy = sk['y0'] + sk['y1'] * em   #y0 + y1*m
    # TODO: figure out if the commented out term of the next line is neccessary under EC
    return sigma_x == Hx * sigma_w and sigma_y == Hy * sigma_w and sigma_z == sk['z'] * sigma_w #and sigma_w != 1


if __name__ == "__main__":
    params = setup(500)
    m = b'my secret identity'
    n = len(m)
    (sk,_) = keygen(params, 1)
    sigma = mac(params, sk, m)
    assert verify(params, sk, m, sigma)