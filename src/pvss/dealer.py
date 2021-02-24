#!/usr/bin/env python3
#from charm.toolbox.integergroup import IntegerGroup

# Distribution

from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from hashlib import sha256


A = tuple([Bn, Bn])
#Polynomial = list([Bn])


class PVSS():

    def __init__(self, params):
        global Gq
        global g
        global p
        global G
        global h
        (Gq, p, g, G, h) = params

    def gen_proof(self, t, n, secret, pub_keys):
        assert n > t
        assert len(pub_keys) == n

        px = self.gen_polynomial(t, secret)

        commitments = self.get_commitments(g, px)
        shares_list = self.calc_shares(px, t, n)

        enc_shares = self.get_encrypted_shares(pub_keys, shares_list)
        X_i_list = self.get_X_i_list(commitments, n)

        pub = {'C_list': commitments, 'Y_list': enc_shares, 'X_list': X_i_list}

        proof = self.DLEQ_prove_list(pub, pub_keys, shares_list)

        # Debug:
        assert len(px) == t-1
        assert len(commitments) == t-1
        assert len(shares_list) == n
        assert shares_list[0] != secret  # I think this is correct
        assert len(enc_shares) == n
        assert len(X_i_list) == n  # Should be n, but we use t in the creation

        return (pub, proof)

    def gen_polynomial(self, t, secret):
        # t-1 constants including secret, thus t-2 random
        px_rand = [p.random() for i in range(t-2)]
        px = [secret] + px_rand
        return px

    def calc_shares(self, px, t, n):
        return [self.calc_poly(px, t, i) for i in range(1, n+1)]

    def calc_poly(self, px, t, x):
        result = 0
        for (alpha, j) in zip(px, range(t)):
            result = (result + alpha * (x**j)) % p
        return result

    def get_commitments(self, g, px):
        return [p_i * g for p_i in px]

    def get_encrypted_shares(self, pub_keys, shares):
        assert len(pub_keys) == len(shares)
        # FIXME: Should we have mod p
        Y_i_list = [shares[i]*y_i for (y_i, i)
                    in zip(pub_keys, range(len(pub_keys)))]
        return Y_i_list

    def get_X_i_list(self, commitments, n):
        return [self.get_X_i(commitments, i) for i in range(1, n+1)]

    def get_X_i(self, C_list, i):
        elements = [(i**j) * C_j for (C_j, j)
                    in zip(C_list, range(len(C_list)))]

        ans = elements[0]
        for e in elements[1:]:
            ans = ans + e

        return ans

    def participant_decrypt(self, x_i, Y_i):
        return x_i.mod_inverse(p) * Y_i

    def participant_decrypt_and_prove(self, x_i, Y_i):
        S_i = self.participant_decrypt(x_i, Y_i)

        y_i = x_i * G
        decrypt_proof = self.DLEQ_prove(G, S_i, y_i, Y_i, x_i)

        return (S_i, decrypt_proof)

    def decode(self, S_list, t):
        assert len(S_list) == t
        ans = self.lagrange(1, t) * S_list[0]
        parts = []
        parts.append(ans)

        for (S_i, i) in zip(S_list[1:], range(2, t+1)):
            ans = ans + self.lagrange(i, t) * S_i

        return ans  # G**s

    def lagrange(self, i, t) -> int:
        res = 1
        for j in range(1, t+1):
            if j != i:
                res = res * j/(j-i)
        return int(res)

    def verify_correct_decryption(self, S_i, Y_i, decrypt_proof, pub_key):
        #import pdb; pdb.set_trace()
        (c_claimed, r, a_1, a_2) = decrypt_proof
        y_i = pub_key

        c = self.hash(G, S_i, a_1, a_2)
        if c != c_claimed:
            return False

        a_1_new = r * G + c * y_i
        a_2_new = r * S_i + c * Y_i
        if a_1 == a_1_new and a_2 == a_2_new:
            return True
        return False

    def batch_verify_correct_decryption(self, proved_decryptions, Y_list, pub_keys):
        for ((S_i, decrypt_proof), Y_i, pub_key) in zip(proved_decryptions, Y_list, pub_keys):
            if self.verify_correct_decryption(S_i, Y_i, decrypt_proof, pub_key) == False:
                return False
        return True

    def DLEQ_prove(self, g_1, g_2, h_1, h_2, x_i):
        w = p.random()
        (a_1, a_2) = self.DLEQ_prover_calc_a(g_1, g_2, w)
        c = self.hash(g_1, g_2, a_1, a_2)
        r = self.DLEQ_calc_r(w, x_i, c)
        return (c, r, a_1, a_2)

    def DLEQ_prover_calc_a(self, g_1, g_2, w):
        a_1 = w * g_1
        a_2 = w * g_2
        return (a_1, a_2)

    def DLEQ_prove_list(self, pub, y_list, shares_list):

        X_list = pub['X_list']
        Y_list = pub['Y_list']

        assert len(X_list) == len(y_list)
        assert len(Y_list) == len(y_list)
        n = len(X_list)

        w_list = [p.random() for i in range(n)]
        a_1_list = [w_list[i] * g for i in range(n)]
        a_2_list = [w_list[i] * y_list[i] for i in range(n)]

        c = self.hash(X_list, Y_list, a_1_list, a_2_list)
        r_list = [self.DLEQ_calc_r(w, alpha, c)
                  for (alpha, w) in zip(shares_list, w_list)]

        proof = {'c': c, 'r_list': r_list,
                 'a_1_list': a_1_list, 'a_2_list': a_2_list}

        return proof

    def hash(self, g_1, g_2, a_1, a_2) -> Bn:
        state = str([g_1, g_2, a_1, a_2])
        H = sha256()
        H.update(state.encode("utf8"))
        hash_c = H.digest()
        c = Bn.from_binary(hash_c) % p
        return c

    def DLEQ_calc_r(self, w, alpha, c):
        r = (w - c * alpha) % p
        return r

    def DLEQ_verify(self, y_list, pub, proof):

        r_list = proof['r_list']
        c_claimed = proof['c']
        a_1_orig_list = proof['a_1_list']
        a_2_orig_list = proof['a_2_list']

        Y_list = pub['Y_list']

        X_list = pvss.get_X_i_list(pub['C_list'], n)

        c = self.hash(X_list, Y_list, a_1_orig_list, a_2_orig_list)

        # Prover lied about c
        if c_claimed != c:
            return False

        for (r_i, X_i, y_i, Y_i, a_1_orig, a_2_orig) in zip(r_list, X_list, y_list, Y_list, a_1_orig_list, a_2_orig_list):
            (a_1_new, a_2_new) = self.DLEQ_verifyer_calc_a(r_i, c, g, X_i, y_i, Y_i)

            if a_1_new != a_1_orig or a_2_new != a_2_orig:
                return False

        return True

    def DLEQ_verifyer_calc_a(self, r, c, g_1, h_1, g_2, h_2):
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
    #cpni = DLEQ(params)
    pvss = PVSS(params)

    n = 4
    t = 3

    demo_priv_keys = [p.random() for i in range(n)]
    demo_pub_keys = [priv_key * G for priv_key in demo_priv_keys]

    (pub, proof) = pvss.gen_proof(t, n, m, demo_pub_keys)

    #proof = pvss.DLEQ_prove_list(pub, demo_pub_keys, shares_list)

    #verifyer_X_list = pvss.get_X_i_list(pub['C_list'], n)

    print("Test verify")
    assert pvss.DLEQ_verify(demo_pub_keys, pub, proof) == True

    expected_decryption = m * G

    proved_decryptions = [pvss.participant_decrypt_and_prove(private_key, share) for (
        private_key, share) in zip(demo_priv_keys, pub['Y_list'])]

    if pvss.batch_verify_correct_decryption(proved_decryptions, pub['Y_list'], demo_pub_keys) == False:
        print("Verification of decryption failed")

    S_list = [S_i for (S_i, decrypt_proof) in proved_decryptions]

    actual_decryption = pvss.decode(S_list[0:-1], t)

    print("Test decrypt")
    assert expected_decryption == actual_decryption

    # TODO:
    # Solve decryption  - DONE
    # DLEQ proof on S_i beeing correct decryption of Y_i - DONE
    # Refactor
