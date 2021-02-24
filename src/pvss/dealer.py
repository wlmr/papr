#!/usr/bin/env python3
#from charm.toolbox.integergroup import IntegerGroup

# Distribution

from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn


class PVSS():

    def __init__(self, params):
        global Gq
        global g
        global p
        global G
        global h
        (Gq, p, g, G, h) = params

    def gen_polynomial(self, t, n, secret, pub_keys):
        assert n > t
        assert len(pub_keys) == n

        enc_secret = secret  # Should we encode it to be on curve?

        # t-1 constants including secret, thus t-2 random
        px_rand = [p.random() for i in range(t-2)]

        px = [enc_secret] + px_rand

        commitments = self.get_commitments(g, px)
        shares_list = [self.calc_poly(px, t, i) for i in range(1, n+1)]

        enc_shares = self.get_encrypted_shares(pub_keys, shares_list)
        X_i_list = self.get_X_i_list(commitments, n)

        # Debug:
        assert len(px) == t-1
        assert len(commitments) == t-1
        assert len(shares_list) == n
        assert shares_list[0] != enc_secret  # I think this is correct
        assert len(enc_shares) == n
        assert len(X_i_list) == n  # Should be n, but we use t in the creation

        pub = {'C_list': commitments, 'Y_list': enc_shares, 'X_list': X_i_list}

        return (pub, shares_list)

    def calc_poly(self, px, t, x):
        result = 0
        for (alpha, j) in zip(px, range(t)):
            result = (result + alpha * (x**j)) % p
        return result

    def get_commitments(self, g, px):
        # Reverse order, why does it not work in default order?
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

    def verify_correct_decryption(self, S_i, Y_i):
        pass

    def participant_decrypt(self, x_i, Y_i):
        return x_i.mod_inverse(p) * Y_i

    def decode(self, S_list, t):
        assert len(S_list) == t
        ans = self.lagrange(1, t) * S_list[0]
        parts = []
        parts.append(ans)

        for (S_i, i) in zip(S_list[1:], range(2, t+1)):  # Invert ??
            ans = ans + self.lagrange(i, t) * S_i

        return ans  # G**s

    def lagrange(self, i, t) -> int:
        res = 1
        for j in range(1, t+1):
            if j != i:
                res = res * (j)/((j-i))
        return int(res)
