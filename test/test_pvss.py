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
        actual_decryption = issuer.decode(S_list[0:-1], t)

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
        actual_decryption = issuer.decode(S_list[0:-1], t)

        # Verify secret
        print("Test decrypt")
        assert expected_decryption == actual_decryption


    def test_another_reconstuction(self):
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

        actual_decryption2 = issuer.decode_debug(S_list[1:4], t, [2,3,4])

        # Verify secret
        print("Test decrypt")
        assert expected_decryption == actual_decryption2

        # import itertools

        # perm = itertools.permutations(zip(S_list, range(t)), t)

        # for permutaion in perm:
        #     (S, i) = permutaion
        #     actual_decryption = issuer.decode_debug(S, i, t)
        #     assert expected_decryption == actual_decryption

    def test_all_reconstuctions(self):
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

        perm = itertools.permutations(S_list, t)

        for permutaion in perm:

            actual_decryption = issuer.decode(permutaion, t)
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
