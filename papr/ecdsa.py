from petlib.ec import EcGroup, Bn
from papr.utils import hash


def sign(p, g, priv_key, m: list):
    r = 0
    s = 0
    while (r == 0 or s == 0):
        k = p.random()
        x, _ = (k * g).get_affine()
        r = x % p
        s = (k.mod_inverse(p) * (hash(m) + r * priv_key)) % p
    return r, s


def verify(G, p, g, r, s, pub_key, m: list):
    if pub_key != G.infinite() and G.check_point(pub_key) and (p * pub_key) == G.infinite():
        u1 = (hash(m) * s.mod_inverse(p)) % p
        u2 = (r * s.mod_inverse(p)) % p
        try:
            x, _ = (u1 * g + u2 * pub_key).get_affine()
        except Exception:
            return False
        if r == (x % p):
            return True
        return False
    else:
        return False


if __name__ == '__main__':
    G = EcGroup(714)
    p = G.order()
    g = G.hash_to_point(b'g')
    h = G.hash_to_point(b'h')
    params = (G, p, g, h)
    print("-----------------------------")
    print("-----------------------------")
    print("should work i.e. return true:")
    print("-----------------------------")
    print("-----------------------------")
    pub_id = p.random() * g
    pub_id_x, _ = pub_id.get_affine()
    x = p.random()
    y = x * g
    r, s = sign(p, g, x, pub_id_x)
    print(verify(G, p, g, r, s, y, pub_id_x))
    print("-----------------------------------")
    print("-----------------------------------")
    print("should NOT work, i.e. return false:")
    print("-----(wrong signing key)-----------")
    print("-----------------------------------")
    x = Bn.from_decimal("100")
    r, s = sign(p, g, x, pub_id_x)
    print(verify(G, p, g, r, s, y, pub_id_x))
    print("-----------------------------------")
    print("-----------------------------------")
    print("should NOT work, i.e. return false:")
    print("-----(changed message key)---------")
    print("-----------------------------------")
    pub_id = p.random() * g
    pub_id_x, _ = pub_id.get_affine()
    x = p.random()
    y = x * g
    r, s = sign(p, g, x, pub_id_x)
    pub_id_x += 1
    print(verify(G, p, g, r, s, y, pub_id_x))
