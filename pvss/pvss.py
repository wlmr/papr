#!/usr/bin/env python3

# from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
# from hashlib import sha256
import pvss.cpni as cpni


A = tuple[Bn, Bn]
# Polynomial = list([Bn])


class PVSS_issuer():

    def __init__(self, params):
        global Gq
        global g
        global p
        global G
        (Gq, p, g, G) = params

    def gen_proof(self, t, n, secret, pub_keys):
        '''
        Generate polynomial and proof
        '''
        assert n > t
        assert len(pub_keys) == n
        # assert secret == secret % (p-1)

        px = self.gen_polynomial(t, secret)

        commitments = self.get_commitments(g, px)
        shares_list = self.calc_shares(px, t, n)

        enc_shares = self.__get_encrypted_shares(pub_keys, shares_list)
        X_i_list = cpni.get_X_i_list(commitments, n)

        pub = {'C_list': commitments, 'Y_list': enc_shares, 'X_list': X_i_list}

        params = (Gq, p, g, G)
        proof = cpni.DLEQ_prove_list(params, pub, pub_keys, shares_list)

        # Debug:
        assert len(px) == t
        assert len(commitments) == t
        assert len(shares_list) == n
        assert shares_list[0] != secret  # I think this is correct
        assert len(enc_shares) == n
        assert len(X_i_list) == n  # Should be n, but we use t in the creation

        return (pub, proof)

    def gen_polynomial(self, t, secret):
        '''
        Generate polynomial
        '''
        px_rand = [p.random() for i in range(t-1)]
        px = [secret] + px_rand
        return px

    def calc_shares(self, px, t, n):
        return [self.__calc_share(px, t, i) for i in range(1, n+1)]

    def __calc_share(self, px, t, x):
        assert len(px) == t
        result = 0
        for (alpha, j) in zip(px, range(t)):
            result = (result + alpha * (x**j)) % p
        return result

    def get_commitments(self, g, px):
        return [p_i * g for p_i in px]

    def __get_encrypted_shares(self, pub_keys, shares):
        assert len(pub_keys) == len(shares)
        # FIXME: Should we have mod p
        Y_i_list = [(shares[i]) * y_i for (y_i, i)
                    in zip(pub_keys, range(len(pub_keys)))]
        return Y_i_list

    # def decode(self, S_list, t):
    #     '''
    #     Calulates secret from participants decrypted shares
    #     '''
    #     assert len(S_list) == t
    #     ans = self.__lagrange(1, t) * S_list[0]

    #     for (S_i, i) in zip(S_list[1:], range(2, t+1)):
    #         ans = ans + self.__lagrange(i, t) * S_i

    #     return ans  # G**s

    def decode(self, S_list, index_list):
        '''
        Calulates secret from participants decrypted shares
        '''
        assert len(S_list) == len(index_list)
        ans = self.__lagrange(index_list[0], index_list) * S_list[0]

        for (S_i, i) in zip(S_list[1:], range(1, len(S_list))):
            ans = ans + self.__lagrange(index_list[i], index_list) * S_i

        return ans  # G**s

    def __lagrange(self, i, index_list) -> int:
        '''
        Calculate lagrange coefficient
        '''
        res = 1
        for j in index_list:
            if j != i:
                res = res * j/(j-i)
        return int(res)

    def verify_correct_decryption(self, S_i, Y_i, decrypt_proof, pub_key):
        params = (Gq, p, g, G)
        return cpni.DLEQ_verify_single(params, G, S_i, pub_key, Y_i, decrypt_proof)

    def batch_verify_correct_decryption(self, proved_decryptions, Y_list, pub_keys):
        '''
        Verify all paricipants decryption of shares
        '''
        for ((S_i, decrypt_proof), Y_i, pub_key) in zip(proved_decryptions, Y_list, pub_keys):
            if self.verify_correct_decryption(S_i, Y_i, decrypt_proof, pub_key) is False:
                return False
        return True


class PVSS_participant():
    def __init__(self, params):
        global Gq
        global g
        global p
        global G
        global x_i
        (Gq, p, g, G) = params

    def generate_key_pair(self):
        self.x_i = p.random()
        y_i = self.x_i * G
        return y_i

    def participant_decrypt(self, Y_i):
        return self.x_i.mod_inverse(p) * Y_i

    def participant_decrypt_and_prove(self, Y_i):
        S_i = self.participant_decrypt(Y_i)

        y_i = self.x_i * G

        params = (Gq, p, g, G)
        decrypt_proof = cpni.DLEQ_prove(params, G, S_i, y_i, Y_i, self.x_i)

        return (S_i, decrypt_proof)
