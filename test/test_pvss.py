#!/usr/bin/env python3
# from pvss import pvss_participant
from petlib.ec import EcGroup
# import pvss.pvss as PVSS
# from pvss import PVSS_participant
# import pvss.pvss_python.pvss as pvss
# from pvss.pvss_participant import PVSS_participant
# import pvss.pvss_python.cpni as cpni
import pvss.pvss_wrapper as pvss
import itertools
import pytest


class TestPvss():
    def test_distribute_secret(self):
        Gq = EcGroup()
        p = Gq.order()
        g = Gq.generator()
        G = Gq.hash_to_point(b'G')
        params = (Gq, p, g, G)

        (k, n) = (3, 4)

        priv_keys = []
        pub_keys = []
        for i in range(n):
            (x_i, y_i) = pvss.helper_generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        secret = p.from_binary(b'This is a test')
        (encrypted_shares, commitments, proof, h) = pvss.distribute_secret(pub_keys, secret, p, k, n, Gq)
        assert pvss.verify_encrypted_shares(encrypted_shares, commitments, pub_keys, proof, h, p)

    def test_decrypt_shares(self):
        Gq = EcGroup()
        p = Gq.order()
        g = Gq.generator()
        G = Gq.hash_to_point(b'G')
        params = (Gq, p, g, G)

        (k, n) = (3, 4)

        priv_keys = []
        pub_keys = []
        for i in range(n):
            (x_i, y_i) = pvss.helper_generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        secret = p.from_binary(b'This is a test')

        (encrypted_shares, commitments, proof, h) = pvss.distribute_secret(pub_keys, secret, p, k, n, Gq)
        # assert verify_encrypted_shares(encrypted_shares, commitments, proof)

        for (x_i, y_i, encrypted_share) in zip(priv_keys, pub_keys, encrypted_shares):
            (decrypted_share, proof_of_decryption) = pvss.participant_decrypt_and_prove(params, x_i, encrypted_share)
            assert pvss.verify_decryption_proof(proof_of_decryption, decrypted_share, encrypted_share, y_i, p, g)
  
    def test_reconstruct(self):
        Gq = EcGroup()
        p = Gq.order()
        g = Gq.generator()
        G = Gq.hash_to_point(b'G')
        params = (Gq, p, g, G)

        (k, n) = (3, 4)

        # participants = [pvss_participant.PVSS_participant(params) for i in range(n)]
        # pub_keys = [participant.generate_key_pair() for participant in participants]
        priv_keys = []
        pub_keys = []
        for i in range(n):
            (x_i, y_i) = pvss.helper_generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        secret = p.from_binary(b'This is a test')

        (encrypted_shares, commitments, proof, h) = pvss.distribute_secret(pub_keys, secret, p, k, n, Gq)
        # assert verify_encrypted_shares(encrypted_shares, commitments, proof)

        decrypted_list = []
        for (x_i, y_i, encrypted_share) in zip(priv_keys, pub_keys, encrypted_shares):
            (decrypted_share, proof_of_decryption) = pvss.participant_decrypt_and_prove(params, x_i, encrypted_share)
            decrypted_list.append(decrypted_share)
            # assert verify_decryption_proof(proof_of_decryption)
        assert pvss.reconstruct(decrypted_list, [1, 2, 3, 4], p) == secret * g
