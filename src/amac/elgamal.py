from charm.toolbox.integergroup import IntegerGroup
from charm.toolbox.PKEnc import PKEnc


class ElGamal(PKEnc):
    """
    Simple Elgamal implementation which lets you import
    the group along with a generator. Encoding/decoding is
    done outside of the implementation. Should be instantiated 
    with ElGamal((G,p,g,h)), where G is a Group of order p, with
    generators g and h
    """

    def __init__(self, params, p=0, q=0):
        global G
        global g
        (G,_,g,_) = params

    def keygen(self):
        x = G.random() 
        h = g ** x
        pk = {'g':g, 'h':h, 'G':G}
        sk = {'x':x}
        return (pk, sk)

    def encrypt(self, pk, m):
        y = pk['G'].random()
        c1 = pk['g'] ** y 
        s = pk['h'] ** y
        c2 = m * s
        return ({'c1':c1, 'c2':c2}, y)

    def decrypt(self, pk, sk, c):
        s = c['c1'] ** sk['x']
        m = c['c2'] * (s ** -1)
        return m

if __name__ == "__main__":
    G = IntegerGroup()
    G.paramgen(100)
    g = G.randomGen()
    h = G.randomGen()
    M = g ** (G.encode(b'god is dead'))
    print(M)
    params = (G, G.p, g, h)
    el = ElGamal(params)
    (pk, sk) = el.keygen()
    (c,r) = el.encrypt(pk, M)
    print(el.decrypt(pk,sk,c) % G.p)