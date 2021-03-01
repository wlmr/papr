#!/usr/bin/env python3

from petlib.ec import EcGroup  # , EcPt
# from petlib.bn import Bn
# from hashlib import sha256
import pvss.pvss as PVSS
import pvss.cpni as cpni
import itertools


class TestPvss():
    def test_full(self):
        # Generate parameters (should be same in other parts of program)
        Gq = EcGroup()
        p = Gq.order()
        g = Gq.generator()
        G = Gq.hash_to_point(b'G')
        params = (Gq, p, g, G)

        # Decide on a secret to be distrubuted
        m = p.from_binary(b'This is a test')

        # Initialize issuer
        issuer = PVSS.PVSS_issuer(params)

        # Set (t,n)-threshold parameters
        n = 4
        t = 3

        # Initiate participants, and generate their key-pairs
        participants = [PVSS.PVSS_participant(params) for i in range(n)]
        pub_keys = [participant.generate_key_pair() for participant in participants]

        # Encrypt secret, create shares and proof
        (pub, proof) = issuer.gen_proof(t, n, m, pub_keys)

        # Prove generates shares validity
        print("Test verify")
        assert cpni.DLEQ_verify_list(params, pub_keys, pub, proof) is True

        # Decryption
        # Calulate what a correct decryption should be
        expected_decryption = m * G

        # Let participants decrypt their shares and generate proofs
        proved_decryptions = [participant.participant_decrypt_and_prove(enc_share) for (participant, enc_share) in zip(participants, pub['Y_list'])]

        # Check participants proofs
        if issuer.batch_verify_correct_decryption(proved_decryptions, pub['Y_list'], pub_keys) is False:
            print("Verification of decryption failed")

        # Use participants decrypted shares to recreate secret
        S_list = [S_i for (S_i, decrypt_proof) in proved_decryptions]
        actual_decryption = issuer.decode(S_list[0:-1], t, [1,2,3])

        # Verify secret
        print("Test decrypt")
        assert expected_decryption == actual_decryption

        # TODO:
        # Solve decryption  - DONE
        # DLEQ proof on S_i beeing correct decryption of Y_i - DONE
        # Refactor

    def test_edge_case(self):
        # Generate parameters (should be same in other parts of program)
        Gq = EcGroup()
        p = Gq.order()
        g = Gq.generator()
        G = Gq.hash_to_point(b'G')
        params = (Gq, p, g, G)

        # Decide on a secret to be distrubuted
        m = p-1

        # Initialize issuer
        issuer = PVSS.PVSS_issuer(params)

        # Set (t,n)-threshold parameters
        n = 4
        t = 3

        # Initiate participants, and generate their key-pairs
        participants = [PVSS.PVSS_participant(params) for i in range(n)]
        pub_keys = [participant.generate_key_pair() for participant in participants]

        # Encrypt secret, create shares and proof
        (pub, proof) = issuer.gen_proof(t, n, m, pub_keys)

        # Prove generates shares validity
        print("Test verify")
        assert cpni.DLEQ_verify_list(params, pub_keys, pub, proof) is True

        # Decryption
        # Calulate what a correct decryption should be
        expected_decryption = m * G

        # Let participants decrypt their shares and generate proofs
        proved_decryptions = [participant.participant_decrypt_and_prove(enc_share) for (participant, enc_share) in zip(participants, pub['Y_list'])]

        # Check participants proofs
        if issuer.batch_verify_correct_decryption(proved_decryptions, pub['Y_list'], pub_keys) is False:
            print("Verification of decryption failed")

        # Use participants decrypted shares to recreate secret
        S_list = [S_i for (S_i, decrypt_proof) in proved_decryptions]
        actual_decryption = issuer.decode(S_list[0:-1], t, range(1,4))

        # Verify secret
        print("Test decrypt")
        assert expected_decryption == actual_decryption


    def helper_function_reconstuct(self, t,n):
        Gq = EcGroup()
        p = Gq.order()
        g = Gq.generator()
        G = Gq.hash_to_point(b'G')
        params = (Gq, p, g, G)

        # Decide on a secret to be distrubuted
        m = p.from_binary(b'This is a test')

        # Initialize issuer
        issuer = PVSS.PVSS_issuer(params)

        # Set (t,n)-threshold parameters
        # n = 4
        # t = 3

        # Initiate participants, and generate their key-pairs
        participants = [PVSS.PVSS_participant(params) for i in range(n)]
        pub_keys = [participant.generate_key_pair() for participant in participants]

        # Encrypt secret, create shares and proof
        (pub, proof) = issuer.gen_proof(t, n, m, pub_keys)

        # Decryption
        # Calulate what a correct decryption should be
        expected_decryption = m * G

        # Let participants decrypt their shares and generate proofs
        proved_decryptions = [participant.participant_decrypt_and_prove(enc_share) for (participant, enc_share) in zip(participants, pub['Y_list'])]
        if issuer.batch_verify_correct_decryption(proved_decryptions, pub['Y_list'], pub_keys) is False:
            print("Verification of decryption failed")
        S_list = [S_i for (S_i, decrypt_proof) in proved_decryptions]
        return (expected_decryption, issuer, S_list)

    def test_another_reconstuction(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        (expected_decryption, issuer, S_list) = self.helper_function_reconstuct(t,n)

        actual_decryption2 = issuer.decode(S_list[1:4], t, [2,3,4])

        # Verify secret
        print("Test decrypt")
        assert expected_decryption == actual_decryption2



    def test_out_of_order_reconstuction(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        (expected_decryption, issuer, S_list) = self.helper_function_reconstuct(t,n)

        new_S_list = [S_list[3], S_list[2], S_list[1]]

        actual_decryption2 = issuer.decode(new_S_list, t, [4,3,2])

        assert expected_decryption == actual_decryption2

       

    def test_another_out_of_order_reconstuction(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        (expected_decryption, issuer, S_list) = self.helper_function_reconstuct(t,n)

        new_S_list = [S_list[2], S_list[1], S_list[0]]
        actual_decryption2 = issuer.decode(new_S_list, t, [3,2,1])
        assert expected_decryption == actual_decryption2

    def test_skipping_one_reconstuction(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        (expected_decryption, issuer, S_list) = self.helper_function_reconstuct(t,n)

        new_S_list = [S_list[0], S_list[2], S_list[3]]
        actual_decryption2 = issuer.decode(new_S_list, t, [1,3,4])

        assert expected_decryption == actual_decryption2

    def test_another_skipping_one_reconstuction(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        (expected_decryption, issuer, S_list) = self.helper_function_reconstuct(t,n)

        new_S_list = [S_list[0], S_list[1], S_list[3]]
        actual_decryption2 = issuer.decode(new_S_list, t, [1,2,4])

        assert expected_decryption == actual_decryption2

        
    def test_all_reconstuctions(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        (expected_decryption, issuer, S_list) = self.helper_function_reconstuct(t,n)

        possible_indexes = range(n)
        permutaions = itertools.permutations(possible_indexes, t)

        for permutaion in permutaions:
            S_list_local = [S_list[i] for i in permutaion]
            index_list = [i+1 for i in permutaion]
            actual_decryption = issuer.decode(S_list_local, t, index_list)
            print(index_list)
            assert expected_decryption == actual_decryption


    def test_gen_polynomial(self):
        Gq = EcGroup()
        p = Gq.order()
        g = Gq.generator()
        G = Gq.hash_to_point(b'G')
        params = (Gq, p, g, G)

        # Decide on a secret to be distrubuted
        m = p.from_binary(b'This is a test')

        # Initialize issuer
        issuer = PVSS.PVSS_issuer(params)

        px = issuer.gen_polynomial(3,42)
        for pi in px:
            assert pi < p



    def test_X_i_calc(self):
        Gq = EcGroup()
        p = Gq.order()
        g = Gq.generator()
        G = Gq.hash_to_point(b'G')
        params = (Gq, p, g, G)

        # Decide on a secret to be distrubuted
        m = p.from_binary(b'This is a test')

        # Initialize issuer
        issuer = PVSS.PVSS_issuer(params)

        t = 3
        n = 4

        participants = [PVSS.PVSS_participant(params) for i in range(n)]
        pub_keys = [participant.generate_key_pair() for participant in participants]

        #(pub,proof) = issuer.gen_proof(t,n,m,pub_keys)

        secret=m
        px = issuer.gen_polynomial(t, secret)

        commitments = issuer.get_commitments(g, px)
        shares_list = issuer.calc_shares(px, t, n)
      


        X_list = cpni.get_X_i_list(commitments, n)

        X_list_verify = [share * g for share in shares_list]

        for (x1,x2) in zip(X_list, X_list_verify):
            assert x1 == x2






