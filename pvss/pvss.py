#!/usr/bin/env python3

from petlib.bn import Bn
import pvss.cpni as cpni

A = tuple[Bn, Bn]


class PVSS():

    def __init__(self):
        pass

    def distribute_secret(self, pub_keys, secret, p, k, n, Gq):
        assert len(pub_keys) == n
        h = p.random() * Gq.hash_to_point(b'h')
        px = self.gen_polynomial(k, secret)
        commitments = self.get_commitments(h, px)
        shares_list = self.calc_shares(px, k, n, p)
        enc_shares = self.__get_encrypted_shares(pub_keys, shares_list)
        proof = cpni.DLEQ_prove_list(p, h, commitments, enc_shares, pub_keys, shares_list)
        return (enc_shares, commitments, proof, h)

    def verify_encrypted_shares(self, encrypted_shares, commitments, pub_keys, proof, h):
        return cpni.DLEQ_verify_list(p=p, g=h, y_list=pub_keys, C_list=commitments, Y_list=encrypted_shares, proof=proof)

    def reconstruct(self, decrypted_list, index_list):
        return self.decode(decrypted_list, index_list)

    def verify_decryption_proof(self, proof_of_decryption, decrypted_share, encrypted_share, pub_key):
        return self.verify_correct_decryption(decrypted_share, encrypted_share, proof_of_decryption, pub_key, p)



    # Helper or older functions
    def gen_proof(self, k, n, secret, pub_keys):
        '''
        Generate polynomial and proof
        '''
        assert n > k
        assert len(pub_keys) == n

        px = self.gen_polynomial(k, secret)
        commitments = self.get_commitments(g, px)
        shares_list = self.calc_shares(px, k, n, p)
        enc_shares = self.__get_encrypted_shares(pub_keys, shares_list)

        pub = {'C_list': commitments, 'Y_list': enc_shares}

        #params = (Gq, p, g, G)
        proof = cpni.DLEQ_prove_list(p, g, commitments, enc_shares, pub_keys, shares_list)

        # Debug:
        assert len(px) == k
        assert len(commitments) == k
        assert len(shares_list) == n
        assert shares_list[0] != secret  # I think this is correct
        assert len(enc_shares) == n

        return (pub, proof)


    def gen_polynomial(self, k, secret):
        '''
        Generate polynomial
        '''
        px_rand = [p.random() for i in range(k-1)]
        px = [secret] + px_rand
        return px

    def calc_shares(self, px, k, n, p):
        '''
        Calculates p(j) for all j (0,n)
        '''
        return [self.__calc_share(px, k, Bn(i), p) for i in range(1, n+1)]

    def __calc_share(self, px, k, x, p):
        '''
        Calculates p(x)
        '''
        assert len(px) == k
        result = 0
        for (alpha, j) in zip(px, range(k)):
            result = (result + alpha * (x**j)) % p
        return result

    def get_commitments(self, g, px):
        '''
        Calculates all commitments C_j for j =[0,k)
        '''
        return [p_i * g for p_i in px]

    def __get_encrypted_shares(self, pub_keys, shares):
        '''
        Calculates the encrypted shares Y_i for all i in (1,n)
        '''
        assert len(pub_keys) == len(shares)
        # FIXME: Should we have mod p
        Y_i_list = [(shares[i]) * y_i for (y_i, i)
                    in zip(pub_keys, range(len(pub_keys)))]
        return Y_i_list

    def decode(self, S_list, index_list):
        '''
        Calulates secret from participants decrypted shares
        '''
        assert len(S_list) == len(index_list)

        ans = self.__lagrange(index_list[0], index_list) * S_list[0]
        for (S_i, i) in zip(S_list[1:], range(1, len(S_list))):
            ans = ans + self.__lagrange(index_list[i], index_list) * S_i
        return ans  # G**s

    def __lagrange(self, i, index_list):
        '''
        Calculate lagrange coefficient
        '''
        top = Bn(1)
        bottom = Bn(1)
        for j in index_list:
            if j != i:
                top = (top * j)
                bottom = (bottom * (j-i))
        return top.mod_mul(bottom.mod_inverse(p), p)

    def verify_correct_decryption(self, S_i, Y_i, decrypt_proof, pub_key, p):
        '''
        Verifies the participants proof of correct decryption of their share
        '''
        #params = (Gq, p, g, G)
        return cpni.DLEQ_verify_single(p, G, S_i, pub_key, Y_i, decrypt_proof)

    def batch_verify_correct_decryption(self, proved_decryptions, Y_list, pub_keys):
        '''
        Verify all paricipants decryption of shares
        '''
        for ((S_i, decrypt_proof), Y_i, pub_key) in zip(proved_decryptions, Y_list, pub_keys):
            if self.verify_correct_decryption(S_i, Y_i, decrypt_proof, pub_key, p) is False:
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
        '''
        Generates a key-pair, stores the private key in this object and returns the public key
        '''
        self.x_i = p.random()
        y_i = self.x_i * G
        return y_i

    def participant_decrypt(self, Y_i):
        '''
        Decrypt a encrypted share with stored private key
        '''
        return self.x_i.mod_inverse(p) * Y_i

    def participant_decrypt_and_prove(self, Y_i):
        '''
        Decrypts a encrypted share with stored private key, and generates proof of it being done correctly.
        '''
        S_i = self.participant_decrypt(Y_i)

        y_i = self.x_i * G
        params = (Gq, p, g, G)
        decrypt_proof = cpni.DLEQ_prove(params, G, S_i, y_i, Y_i, self.x_i)
        return (S_i, decrypt_proof)

    def get_pub_key(self):
        y_i = self.x_i * G
        return y_i
