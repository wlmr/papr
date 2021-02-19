from petlib.ec import EcGroup
from petlib.bn import Bn

#TODO: decide whether this class should be exponential elgamal,
# i.e. m gets raised to g in the algorithm itself.
class ElGamal():
    """
    Simple Elgamal implementation which lets you import
    the group along with a generator. Encoding/decoding is
    done outside of the implementation. Should be instantiated 
    with ElGamal((G,p,g,h)), where G is a Group of order p, with
    generators g and h
    """

    def __init__(self, params):
        global G
        global g
        global p
        (G,p,g,_) = params

    def keygen(self):
        x = p.random() 
        h = x * g
        pk = {'g':g, 'h':h, 'p':p}
        sk = {'x':x}
        return (pk, sk)

    def encrypt(self, pk, m):
        y = pk['p'].random()
        c1 = y * pk['g'] 
        s = y * pk['h'] 
        c2 = m + s
        return ({'c1':c1, 'c2':c2}, y)

    def decrypt(self, sk, c):
        return c['c2'] - sk['x'] * c['c1']

if __name__ == "__main__":
    G = EcGroup()
    p = G.order()
    g = G.generator()
    h = G.hash_to_point(b"h")

    m = Bn.from_binary(b'god is dead') * g
    params = (G, p, g, h)
    el = ElGamal(params)
    (pk, sk) = el.keygen()
    (c,r) = el.encrypt(pk, m)
    print(el.decrypt(pk,sk,c))