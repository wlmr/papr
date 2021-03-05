#!/usr/bin/env python3

# from typing import Any
# from petlib.bn import Bn
# from petlib.ec import EcGroup, EcPt
import pvss.cpni as cpni

from pvss.pvss import decrypted_share_type, single_proof_type


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

    def participant_decrypt_and_prove(self, Y_i) -> tuple[decrypted_share_type, single_proof_type]:
        '''
        Decrypts a encrypted share with stored private key, and generates proof of it being done correctly.
        '''
        S_i = self.participant_decrypt(Y_i)

        y_i = self.x_i * G
        params = (Gq, p, g, G)
        decrypt_proof = cpni.DLEQ_prove(params, G, S_i, y_i, Y_i, self.x_i)
        return S_i, decrypt_proof

    def get_pub_key(self):
        y_i = self.x_i * G
        return y_i
