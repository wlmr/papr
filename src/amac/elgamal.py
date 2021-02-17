#from charm.toolbox.integergroup import IntegerGroup
from charm.toolbox.PKEnc import PKEnc
from charm.toolbox.ecgroup import ECGroup, G, ZR, order 
from charm.toolbox.eccurve import prime192v2

class ElGamal(PKEnc):
    """
    Simple Elgamal implementation which lets you import
    the group along with a generator. Encoding/decoding is
    done outside of the implementation. Should be instantiated 
    with ElGamal((G,p,g,h)), where G is a Group of order p, with
    generators g and h
    """

    def __init__(self, params):
        global group
        global g
        (group,_,g,_) = params

    def keygen(self):
        x = group.random(ZR) 
        h = g ** x
        pk = {'g':g, 'h':h, 'G':group}
        sk = {'x':x}
        return (pk, sk)

    def encrypt(self, pk, m):
        y = pk['G'].random(ZR)
        c1 = pk['g'] ** y 
        s = pk['h'] ** y 
        c2 = (pk['g']**m) * s
        return ({'c1':c1, 'c2':c2}, y)

    def decrypt(self, pk, sk, c):
        s = c['c1'] * sk['x']
        m = c['c2'] * (s ** -1)
        return m#c['c2'] - pk['x']*c['c1']

if __name__ == "__main__":
    group = ECGroup(prime192v2)
    g = group.random(G)
    h = group.random(G)
    M = g * group.encode(b'god is dead         ')
    #print(M)
    params = (group, group.order(), g, h)
    el = ElGamal(params)
    (pk, sk) = el.keygen()
    (c,r) = el.encrypt(pk, M)
    print(el.decrypt(pk,sk,c))