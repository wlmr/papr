#!/usr/bin/env python3
from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from dealer import PVSS
from hashlib import sha256


class DLEQ():

    def __init__(self, params):
        global G
        global g
        global p
        global G
        global h
        (Gq, p, g, G, h) = params
        
        
    def DLEQ_prove(self, pub, y_list, p_of_i):

        X_list = pub['X_list']
        Y_list = pub['Y_list']

        assert len(X_list) == len(y_list)
        assert len(Y_list) == len(y_list)
        n = len(X_list)

        w_list = [p.random() for i in range(n)]
        a_1_list = [w_list[i] * g for i in range(n)]
        a_2_list = [w_list[i] * y_list[i] for i in range(n)]

        c = self.hash(X_list, Y_list, a_1_list, a_2_list)
        r_list = [self.calc_r(w, alpha, c)
                  for (alpha, w) in zip(p_of_i, w_list)]

        proof = {'c': c, 'r_list': r_list,
                 'a_1_list': a_1_list, 'a_2_list': a_2_list}

        return proof

    def hash(self, X_list, Y_list, a_1_list, a_2_list):
        state = str([X_list[:], Y_list[:], a_1_list[:], a_2_list[:]])
        H = sha256()
        H.update(state.encode("utf8"))
        hash_c = H.digest()
        c = Bn.from_binary(hash_c) % p
        return c

    def calc_r(self, w, alpha, c):
        r = (w - c * alpha) % p
        return r

    def DLEQ_verify(self, params, y_list, X_list, Y_list, proof):
        r_list = proof['r_list']
        c = proof['c']
        a_1_orig_list = proof['a_1_list']
        a_2_orig_list = proof['a_2_list']

        for (r_i, X_i, y_i, Y_i, a_1_orig, a_2_orig) in zip(r_list, X_list, y_list, Y_list, a_1_orig_list, a_2_orig_list):
            (a_1_new, a_2_new) = self.DLEQ_verifyer_2(
                params, r_i, c, g, X_i, y_i, Y_i)

            if a_1_new != a_1_orig or a_2_new != a_2_orig:
                return False

        return True

    def DLEQ_verifyer_2(self, params, r, c, g_1, h_1, g_2, h_2):
        a_1 = r * g_1 + c * h_1
        a_2 = r * g_2 + c * h_2
        return (a_1, a_2)


if __name__ == "__main__":
    Gq = EcGroup()
    p = Gq.order()
    g = Gq.generator()
    G = Gq.hash_to_point(b'G')
    h = Gq.hash_to_point("mac_ggm".encode("utf8"))

    m = Bn.from_binary(b'This is a test')
 
    params = (Gq, p, g, G, h)
    cpni = DLEQ(params)
    pvss = PVSS(params)

    n = 4
    t = 3

    demo_priv_keys = [p.random() for i in range(n)]
    demo_pub_keys = [priv_key * G for priv_key in demo_priv_keys] 

    (pub, shares_list) = pvss.gen_polynomial(t, n, m, demo_pub_keys)

    proof = cpni.DLEQ_prove(pub, demo_pub_keys, shares_list)

    verifyer_X_list = pvss.get_X_i_list(pub['C_list'], n)

    assert cpni.DLEQ_verify(params, demo_pub_keys,
                            verifyer_X_list, pub['Y_list'], proof) == True

    expected_decryption = m * G

    S_list = [pvss.participant_decrypt(private_key, share) for (
        private_key, share) in zip(demo_priv_keys, pub['Y_list'])]

    actual_decryption = pvss.decode(S_list[0:-1], t)

    assert expected_decryption == actual_decryption

    # TODO:
    # Solve decryption  - DONE
    # DLEQ proof on S_i beeing correct decryption of Y_i
    # Refactor
