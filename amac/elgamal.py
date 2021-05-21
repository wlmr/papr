from petlib.ec import EcGroup


def keygen(params):
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