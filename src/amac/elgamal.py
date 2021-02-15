from charm.toolbox.integergroup import IntegerGroup
from charm.toolbox.PKEnc import PKEnc


class ElGamal(PKEnc):

    def __init__(self, params, p=0, q=0):
        global G
        global g
        (G,_,g,_) = params

    def keygen(self):
        x = G.random() 
        h = g ** x
        pk = {'g':g, 'h':h}
        sk = {'x':x}
        return (pk, sk)

    def encrypt(self, pk, M):
        y = G.random()
        c1 = pk['g'] ** y 
        s = pk['h'] ** y
        c2 = M * s
        return ({'c1':c1, 'c2':c2}, y)

    def decrypt(self, pk, sk, c):
        s = c['c1'] ** sk['x']
        m = c['c2'] * (s ** -1)
        if G.groupSetting() == 'integer':
            M = G.decode(m % G.p)
        elif G.groupSetting() == 'elliptic_curve':
            M = G.decode(m)
        return M

def test():
    G = IntegerGroup()
    G.paramgen(100)
    g = G.randomGen()
    h = G.randomGen()
    m = G.encode(b'god is dead')
    params = (G, G.p, g, h)
    el = ElGamal(params)
    (pk, sk) = el.keygen()
    (c,r) = el.encrypt(pk, m)
    print(el.decrypt(pk,sk,c))


test()
