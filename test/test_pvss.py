#!/usr/bin/env python3
from pvss import pvss_participant
from petlib.ec import EcGroup
# import pvss.pvss as PVSS
# from pvss import PVSS_participant
import pvss.pvss as pvss
# from pvss.pvss_participant import PVSS_participant
import pvss.cpni as cpni
import itertools


class TestPvss():
    def test_distribute_secret(self):
        Gq = EcGroup()
        p = Gq.order()
        g = Gq.generator()
        G = Gq.hash_to_point(b'G')
        params = (Gq, p, g, G)

        (k, n) = (3, 4)

        # participants = [pvss_participant.PVSS_participant(params) for i in range(n)]

        #  pub_keys = [participant.generate_key_pair() for participant in participants]

        priv_keys = []
        pub_keys = []
        for i in range(n):
            (x_i, y_i) = pvss.generate_key_pair(params)
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

        # participants = [PVSS_participant(params) for i in range(n)]
        # pub_keys = [participant.generate_key_pair() for participant in participants]
        priv_keys = []
        pub_keys = []
        for i in range(n):
            (x_i, y_i) = pvss.generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)
        
        secret = p.from_binary(b'This is a test')

        (encrypted_shares, commitments, proof, h) = pvss.distribute_secret(pub_keys, secret, p, k, n, Gq)
        # assert verify_encrypted_shares(encrypted_shares, commitments, proof)

        for (x_i, y_i, encrypted_share) in zip(priv_keys, pub_keys, encrypted_shares):
            (decrypted_share, proof_of_decryption) = pvss.participant_decrypt_and_prove(params, x_i, encrypted_share)
            assert pvss.verify_decryption_proof(proof_of_decryption, decrypted_share, encrypted_share, y_i, p, G)

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
            (x_i, y_i) = pvss.generate_key_pair(params)
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
        assert pvss.reconstruct(decrypted_list, [1, 2, 3, 4], p) == secret * G

    def test_full(self):
        # Generate parameters (should be same in other parts of program)
        Gq = EcGroup()
        p = Gq.order()
        g = Gq.generator()
        G = Gq.hash_to_point(b'G')
        params = (Gq, p, g, G)

        # Decide on a secret to be distributed
        m = p.from_binary(b'This is a test')

        # Set (t,n)-threshold parameters
        n = 4
        t = 3

        # Initiate participants, and generate their key-pairs
        #participants = [pvss_participant.PVSS_participant(params) for i in range(n)]
        #pub_keys = [participant.generate_key_pair() for participant in participants]
        priv_keys = []
        pub_keys = []
        for i in range(n):
            (x_i, y_i) = pvss.generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        # Encrypt secret, create shares and proof
        (pub, proof) = pvss.gen_proof(params, t, n, m, pub_keys)

        # Prove generates shares validity
        print("Test verify")
        Y_list = pub['Y_list']
        C_list = pub['C_list']
        assert cpni.DLEQ_verify_list(p, g, pub_keys, C_list, Y_list, proof) is True

        # Decryption
        # Calculate what a correct decryption should be
        expected_decryption = m * G

        # Let participants decrypt their shares and generate proofs
        proved_decryptions = [pvss.participant_decrypt_and_prove(params, x_i, enc_share) for (x_i, enc_share) in zip(priv_keys, pub['Y_list'])]

        # Check participants proofs
        if pvss.batch_verify_correct_decryption(proved_decryptions, pub['Y_list'], pub_keys, p, G) is False:
            print("Verification of decryption failed")

        # Use participants decrypted shares to recreate secret
        S_list = [S_i for (S_i, decrypt_proof) in proved_decryptions]
        actual_decryption = pvss.decode(S_list[0:-1], [1, 2, 3], p)

        # Verify secret
        print("Test decrypt")
        assert expected_decryption == actual_decryption

    def test_edge_case(self):
        # Generate parameters (should be same in other parts of program)
        Gq = EcGroup()
        p = Gq.order()
        g = Gq.generator()
        G = Gq.hash_to_point(b'G')
        params = (Gq, p, g, G)

        # Decide on a secret to be distrubuted
        m = p-1

        # Set (t,n)-threshold parameters
        n = 4
        t = 3

        # Initiate participants, and generate their key-pairs
        # participants = [pvss_participant.PVSS_participant(params) for i in range(n)]
        # pub_keys = [participant.generate_key_pair() for participant in participants]
        priv_keys = []
        pub_keys = []
        for i in range(n):
            (x_i, y_i) = pvss.generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        # Encrypt secret, create shares and proof
        (pub, proof) = pvss.gen_proof(params, t, n, m, pub_keys)

        # Prove generates shares validity
        print("Test verify")
        Y_list = pub['Y_list']
        C_list = pub['C_list']
        assert cpni.DLEQ_verify_list(p, g, pub_keys, C_list, Y_list, proof) is True

        # Decryption
        # Calculate what a correct decryption should be
        expected_decryption = m * G

        # Let participants decrypt their shares and generate proofs
        proved_decryptions = [pvss.participant_decrypt_and_prove(params, x_i, enc_share) for (x_i, enc_share) in zip(priv_keys, pub['Y_list'])]

        # Check participants proofs
        if pvss.batch_verify_correct_decryption(proved_decryptions, pub['Y_list'], pub_keys, p, G) is False:
            print("Verification of decryption failed")

        # Use participants decrypted shares to recreate secret
        S_list = [S_i for (S_i, decrypt_proof) in proved_decryptions]
        actual_decryption = pvss.decode(S_list[0:-1], range(1, 4), p)

        # Verify secret
        print("Test decrypt")
        assert expected_decryption == actual_decryption

    def helper_function_reconstruct(self, t, n):
        Gq = EcGroup()
        p = Gq.order()
        g = Gq.generator()
        G = Gq.hash_to_point(b'G')
        params = (Gq, p, g, G)

        # Decide on a secret to be distributed
        m = p.from_binary(b'This is a test')

        # Initiate participants, and generate their key-pairs
        # participants = [pvss_participant.PVSS_participant(params) for i in range(n)]
        # pub_keys = [participant.generate_key_pair() for participant in participants]
        priv_keys = []
        pub_keys = []
        for i in range(n):
            (x_i, y_i) = pvss.generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        # Encrypt secret, create shares and proof
        (pub, proof) = pvss.gen_proof(params, t, n, m, pub_keys)

        # Decryption
        # Calculate what a correct decryption should be
        expected_decryption = m * G

        # Let participants decrypt their shares and generate proofs
        proved_decryptions = [pvss.participant_decrypt_and_prove(params, x_i, enc_share) for (x_i, enc_share) in zip(priv_keys, pub['Y_list'])]
        if pvss.batch_verify_correct_decryption(proved_decryptions, pub['Y_list'], pub_keys, p, G) is False:
            print("Verification of decryption failed")
        S_list = [S_i for (S_i, decrypt_proof) in proved_decryptions]
        return (expected_decryption, S_list, p)

    def helper_function_reconstuct_and_test(self, t, n, index_list):
        (expected_decryption, S_list, p) = self.helper_function_reconstruct(t, n)

        new_S_list = [S_list[index_list[0]-1], S_list[index_list[1]-1], S_list[index_list[2]-1]]
        actual_decryption2 = pvss.decode(new_S_list, index_list, p)

        assert expected_decryption == actual_decryption2

    def test_another_reconstuction(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [2, 3, 4])

    def test_1_2_3(self):
        # Set (t,n)-threshold parameters
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [1, 2, 3])

    def test_1_2_4(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [1, 2, 4])

    def test_1_3_2(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [1, 3, 2])

    def test_1_3_4(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [1, 3, 4])

    def test_1_4_2(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [1, 4, 2])

    def test_1_4_3(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [1, 4, 3])

    def test_2_1_3(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [2, 1, 3])

    def test_2_1_4(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [2, 1, 4])

    def test_2_3_1(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [2, 3, 1])

    def test_2_3_4(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [2, 3, 4])

    def test_2_4_1(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [2, 4, 1])

    def test_2_4_3(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [2, 4, 3])

    def test_3_1_2(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [3, 1, 2])

    def test_3_1_4(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [3, 1, 4])

    def test_3_2_1(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [3, 2, 1])

    def test_3_2_4(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [3, 2, 4])

    def test_3_4_1(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [3, 4, 1])

    def test_3_4_2(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [3, 4, 1])

    def test_4_1_2(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [4, 1, 2])

    def test_4_1_3(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [4, 1, 3])

    def test_4_2_1(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [4, 2, 1])

    def test_4_2_3(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [4, 2, 3])

    def test_4_3_1(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [4, 3, 1])

    def test_4_3_2(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [4, 3, 2])

    def test_all_reconstuctions(self):
        # Set (t,n)-threshold parameters
        n = 20
        t = 5
        (expected_decryption, S_list, p) = self.helper_function_reconstruct(t, n)

        possible_indexes = range(n)
        permutaions = itertools.combinations(possible_indexes, t)

        for permutaion in permutaions:
            S_list_local = [S_list[i] for i in permutaion]
            index_list = [i+1 for i in permutaion]
            actual_decryption = pvss.decode(S_list_local, index_list, p)

            assert expected_decryption == actual_decryption

    def test_gen_polynomial(self):
        Gq = EcGroup()
        p = Gq.order()
        # g = Gq.generator()
        # G = Gq.hash_to_point(b'G')
        # params = (Gq, p, g, G)

        px = pvss.gen_polynomial(3, 42, p)
        for pi in px:
            assert pi < p

    def test_X_i_calc(self):
        Gq = EcGroup()
        p = Gq.order()
        g = Gq.generator()
        # G = Gq.hash_to_point(b'G')
        # params = (Gq, p, g, G)

        # Decide on a secret to be distrubuted
        m = p.from_binary(b'This is a test')

        t = 3
        n = 4

        secret = m
        px = pvss.gen_polynomial(t, secret, p)

        commitments = pvss.get_commitments(g, px)
        shares_list = pvss.calc_shares(px, t, n, p)

        X_list = cpni.get_X_i_list(commitments, n)

        X_list_verify = [share * g for share in shares_list]

        for (x1, x2) in zip(X_list, X_list_verify):
            assert x1 == x2
