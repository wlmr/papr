from petlib.ec import EcGroup
from petlib.bn import Bn


def keygen(params):
    """
    Simple exponential Elgamal implementation which lets you import
    the group along with a generator. Encoding/decoding is
    done outside of the implementation. Should be instantiated
    with ElGamal((G,p,g,h)), where G is a Group of order p, with
    generators g and h
    """
    (g, p) = params
    x = p.random()
    h = x * g
    pk = {'g': g, 'h': h, 'p': p}
    sk = {'x': x}
    return (pk, sk)


def encrypt(pk, m):
    y = pk['p'].random()
    c1 = y * pk['g']
    c2 = m * pk['g'] + y * pk['h']
    return ({'c1': c1, 'c2': c2}, y)


def decrypt(sk, ciphertext):
    return ciphertext['c2'] - sk['x'] * ciphertext['c1']


if __name__ == "__main__":
    G = EcGroup()
    p = G.order()
    g = G.generator()

    m = Bn.from_binary(b'god is dead')
    params = (g, p)
    (pk, sk) = keygen(params)
    (ciphertext, r) = encrypt(pk, m)
    print(decrypt(sk, ciphertext))
