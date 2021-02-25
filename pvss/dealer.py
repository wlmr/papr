#!/usr/bin/env python3

from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from hashlib import sha256
import chaum_pedersen_non_interactive as cpni


A = tuple[Bn, Bn]
#Polynomial = list([Bn])


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
        assert secret == secret % p

        px = self.__gen_polynomial(t, secret)

        commitments = self.__get_commitments(g, px)
        shares_list = self.__calc_shares(px, t, n)

        enc_shares = self.__get_encrypted_shares(pub_keys, shares_list)
        X_i_list = cpni.get_X_i_list(commitments, n)

        pub = {'C_list': commitments, 'Y_list': enc_shares, 'X_list': X_i_list}

        proof = cpni.DLEQ_prove_list(params, pub, pub_keys, shares_list)

        # Debug:
        assert len(px) == t
        assert len(commitments) == t
        assert len(shares_list) == n
        assert shares_list[0] != secret  # I think this is correct
        assert len(enc_shares) == n
        assert len(X_i_list) == n  # Should be n, but we use t in the creation

        return (pub, proof)

    def __gen_polynomial(self, t, secret):
        '''
        Generate polynomial
        '''
        px_rand = [p.random() for i in range(t-1)]
        px = [secret] + px_rand
        return px

    def __calc_shares(self, px, t, n):
        return [self.__calc_share(px, t, i) for i in range(1, n+1)]

    def __calc_share(self, px, t, x):
        result = 0
        for (alpha, j) in zip(px, range(t)):
            result = (result + alpha * (x**j)) % p
        return result

    def __get_commitments(self, g, px):
        return [p_i * g for p_i in px]

    def __get_encrypted_shares(self, pub_keys, shares):
        assert len(pub_keys) == len(shares)
        # FIXME: Should we have mod p
        Y_i_list = [shares[i]*y_i for (y_i, i)
                    in zip(pub_keys, range(len(pub_keys)))]
        return Y_i_list

    def decode(self, S_list, t):
        '''
        Calulates secret from participants decrypted shares
        '''
        assert len(S_list) == t
        ans = self.__lagrange(1, t) * S_list[0]

        for (S_i, i) in zip(S_list[1:], range(2, t+1)):
            ans = ans + self.__lagrange(i, t) * S_i

        return ans  # G**s

    def __lagrange(self, i, t) -> int:
        '''
        Calculate lagrange coefficient
        '''
        res = 1
        for j in range(1, t+1):
            if j != i:
                res = res * j/(j-i)
        return int(res)



    def verify_correct_decryption(self, S_i, Y_i, decrypt_proof, pub_key):
        '''
        Verify that a participants proof of correct decryption of their share
        '''
        (c_claimed, r, a_1, a_2) = decrypt_proof
        y_i = pub_key

        c = cpni.hash(params, G, S_i, a_1, a_2)
        if c != c_claimed:
            return False

        a_1_new = r * G + c * y_i
        a_2_new = r * S_i + c * Y_i
        if a_1 == a_1_new and a_2 == a_2_new:
            return True
        return False

    def batch_verify_correct_decryption(self, proved_decryptions, Y_list, pub_keys):
        '''
        Verify all paricipants decryption of shares
        '''
        for ((S_i, decrypt_proof), Y_i, pub_key) in zip(proved_decryptions, Y_list, pub_keys):
            if self.verify_correct_decryption(S_i, Y_i, decrypt_proof, pub_key) == False:
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
        decrypt_proof = cpni.DLEQ_prove(params, G, S_i, y_i, Y_i, self.x_i)

        return (S_i, decrypt_proof)




if __name__ == "__main__":
    Gq = EcGroup()
    p = Gq.order()
    g = Gq.generator()
    G = Gq.hash_to_point(b'G')

    m = p.from_binary(b'This is a test')

    params = (Gq, p, g, G)
#    cp = DLEQ(params)
    issuer = PVSS_issuer(params)

    n = 4
    t = 3

    #demo_priv_keys = [p.random() for i in range(n)]
    participants = [PVSS_participant(params) for i in range(n)]
    pub_keys = [participant.generate_key_pair() for participant in participants]

    #demo_pub_keys = [priv_key * G for priv_key in demo_priv_keys]

    (pub, proof) = issuer.gen_proof(t, n, m, pub_keys)

    #proof = pvss.DLEQ_prove_list(pub, demo_pub_keys, shares_list)

    #verifyer_X_list = pvss.get_X_i_list(pub['C_list'], n)

    print("Test verify")
    assert cpni.DLEQ_verify(params, pub_keys, pub, proof) == True

    # Decryption
    expected_decryption = m * G

    #proved_decryptions = [pvss.participant_decrypt_and_prove(private_key, enc_share) for (
    #    private_key, enc_share) in zip(demo_priv_keys, pub['Y_list'])]


    proved_decryptions = [participant.participant_decrypt_and_prove(enc_share) for (participant, enc_share) in zip(participants, pub['Y_list'])]

    if issuer.batch_verify_correct_decryption(proved_decryptions, pub['Y_list'], pub_keys) == False:
        print("Verification of decryption failed")

    S_list = [S_i for (S_i, decrypt_proof) in proved_decryptions]

    actual_decryption = issuer.decode(S_list[0:-1], t)

    print("Test decrypt")
    assert expected_decryption == actual_decryption

    # TODO:
    # Solve decryption  - DONE
    # DLEQ proof on S_i beeing correct decryption of Y_i - DONE
    # Refactor
