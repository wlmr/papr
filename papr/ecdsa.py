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
