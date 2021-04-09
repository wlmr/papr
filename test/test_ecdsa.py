from petlib.ec import EcGroup
from papr.ecdsa import sign, verify


class TestECDSA():

    def test_ecdsa_correct(self):
        G = EcGroup(714)
        p = G.order()
        g = G.hash_to_point(b'g')
        x = p.random()
        y = x * g
        r, s = sign(p, g, x, [y])
        assert verify(G, p, g, r, s, y, [y])

    def test_ecdsa_wrong_message(self):
        G = EcGroup(714)
        p = G.order()
        g = G.hash_to_point(b'g')
        x = p.random()
        y = x * g
        r, s = sign(p, g, x, [y])
        assert not verify(G, p, g, r, s, y, [x])

    def test_ecdsa_wrong_pub_key(self):
        G = EcGroup(714)
        p = G.order()
        g = G.hash_to_point(b'g')
        x = p.random()
        y = (x+3) * g
        r, s = sign(p, g, x, [y])
        assert not verify(G, p, g, r, s, y, [y])

    def test_ecdsa_wrong_priv_key(self):
        G = EcGroup(714)
        p = G.order()
        g = G.hash_to_point(b'g')
        x = p.random()
        y = x * g
        r, s = sign(p, g, x+2, [y])
        assert not verify(G, p, g, r, s, y, [y])
