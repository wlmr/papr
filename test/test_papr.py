from papr.legacy.papr_procedures import restore, setup, enroll
from papr.legacy.papr_procedures import req_cred_eq_id, iss_cred_eq_id
from papr.legacy.papr_procedures import req_cred_anon_auth
from papr.legacy.papr_procedures import data_distrubution_issuer_verify, \
    data_distrubution_commit_encrypt_prove, data_distrubution_random_commit, data_distrubution_select, data_distrubution_verify_commit, \
    iss_cred_data_dist_1, iss_cred_data_dist_2, iss_cred_data_dist_3, req_cred_data_dist_1, req_cred_data_dist_2, req_cred_data_dist_3
from papr.ecdsa import verify
import pvss.pvss as pvss


class TestPapr:

    def test_enroll(self):
        id = "Wilmer Nilsson"
        params, (x_sign, x_encr), (y_sign, y_encr), (iparams, i_sk), sys_list, user_list, cred_list, rev_list, res_list = setup(3, 10)
        (G, p, g0, _) = params
        ret = enroll(params, id, iparams, i_sk, x_sign, user_list)
        assert ret is not None
        t_id, (r, s), priv_id, pub_id, user_list = ret
        print(f"user_list.peek():   {user_list.peek()}\n")
        assert user_list.has("Wilmer Nilsson", 0)
        assert verify(G, p, g0, r, s, y_sign, (id, pub_id))

    def test_eq_id(self):
        id = "Wilmer Nilsson"
        params, (x_sign, _), (_, _), (iparams, i_sk), _, user_list, _, _, _ = setup(3, 10)
        (_, p, g0, _) = params
        ret = enroll(params, id, iparams, i_sk, x_sign, user_list)
        assert ret is not None
        t_id, _, priv_id, _, user_list = ret
        (u, cl, _), _, z = req_cred_anon_auth(params, iparams, t_id, priv_id)
        h = p.random() * g0  # making up a random generator (supposed to come from data distribution)
        c0 = priv_id * h
        y, c, gamma = req_cred_eq_id(params, u, h, priv_id, z, cl, c0)
        assert iss_cred_eq_id(params, u, h, y, c, gamma, cl, c0)

    def test_data_distrubution(self):
        (k, n) = (3, 10)

        params, (x_sign, x_encr), (y_sign, y_encr), (iparams, i_sk), sys_list, user_list, cred_list, rev_list, res_list = setup(k, n)

        (_, p, _, _) = params
        priv_keys = []
        pub_keys = []
        for i in range(n*2):
            (x_i, y_i) = pvss.helper_generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        (my_priv_key, my_pub_key) = pvss.helper_generate_key_pair(params)

        # r1 = data_distrubution_U_1(params)
        # r2 = data_distrubution_I_1(params)

        (c1, r1) = data_distrubution_random_commit(params)
        (c2, r2) = data_distrubution_random_commit(params)
        # Both publishes their commits. When they recive the other ones commit they send their random value.
        # and verifyes that the commit and random value they recived are correct.
        assert data_distrubution_verify_commit(params, c1, r1)
        assert data_distrubution_verify_commit(params, c2, r2)

        selected_pub_keys = data_distrubution_select(pub_keys, r1, r2, n, p)
        E_list, C_list, proof, group_generator = data_distrubution_commit_encrypt_prove(params, my_priv_key, selected_pub_keys, k, n)

        assert data_distrubution_issuer_verify(E_list, C_list, proof, selected_pub_keys, group_generator, p)

    def test_data_distrubution_2(self):

        # r1 U generates a random number and commitment req_cred_data_dist_1 and sends the commitment to I.
        # i1 I stores the commitment, generates a random value with commitment and sends commitment to U.
        # r2 U sends the commited to random value to I.
        # i2 I responds with their random value. **??** And calculates which custodians to use and stores it.
        # r3 U recives the random value and calulates the custodians, and generates a encrypted shares to the custodians, commitments and proof
        # i3 I verifies proof. If valid. Proof of identity is initaited.
        (k, n) = (3, 10)

        params, (x_sign, x_encr), (y_sign, y_encr), (iparams, i_sk), sys_list, user_list, cred_list, rev_list, res_list = setup(k, n)

        (_, p, _, _) = params
        priv_keys = []
        pub_keys = []
        for i in range(n*2):
            (x_i, y_i) = pvss.helper_generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        (my_priv_key, my_pub_key) = pvss.helper_generate_key_pair(params)

        # r1 = data_distrubution_U_1(params)
        # r2 = data_distrubution_I_1(params)

        (requester_commit, requester_random) = req_cred_data_dist_1(params)
        (issuer_commit, issuer_random) = iss_cred_data_dist_1(params)
        # Both publishes their commits. When they recive the other ones commit they send their random value.
        # and verifyes that the commit and random value they recived are correct.
        assert req_cred_data_dist_2(params, issuer_commit, issuer_random) is True
        custodian_list = iss_cred_data_dist_2(params, requester_commit, requester_random, issuer_random, pub_keys, n)
        assert custodian_list is not None

        E_list, C_list, proof, group_generator = req_cred_data_dist_3(params, requester_random, issuer_random, my_priv_key, pub_keys, k, n)

        # selected_pub_keys = data_distrubution_select(pub_keys, r1, r2, n, p)
        # E_list, C_list, proof, group_generator = data_distrubution_U_2(params, my_priv_key, selected_pub_keys, k, n)

        assert iss_cred_data_dist_3(params, E_list, C_list, proof, custodian_list, group_generator)

    def test_restore(self):
        (k, n) = (3, 10)

        params, (x_sign, x_encr), (y_sign, y_encr), (iparams, i_sk), sys_list, user_list, cred_list, rev_list, res_list = setup(k, n)

        (_, p, _, _) = params
        priv_keys = []
        pub_keys = []
        for i in range(n*2):
            (x_i, y_i) = pvss.helper_generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        (my_priv_key, my_pub_key) = pvss.helper_generate_key_pair(params)

        # r1 = data_distrubution_U_1(params)
        # r2 = data_distrubution_I_1(params)

        (requester_commit, requester_random) = req_cred_data_dist_1(params)
        (issuer_commit, issuer_random) = iss_cred_data_dist_1(params)
        # Both publishes their commits. When they recive the other ones commit they send their random value.
        # and verifyes that the commit and random value they recived are correct.
        assert req_cred_data_dist_2(params, issuer_commit, issuer_random) is True
        custodian_list = iss_cred_data_dist_2(params, requester_commit, requester_random, issuer_random, pub_keys, n)
        assert custodian_list is not None

        E_list, C_list, proof, group_generator = req_cred_data_dist_3(params, requester_random, issuer_random, my_priv_key, pub_keys, k, n)

        # selected_pub_keys = data_distrubution_select(pub_keys, r1, r2, n, p)
        # E_list, C_list, proof, group_generator = data_distrubution_U_2(params, my_priv_key, selected_pub_keys, k, n)

        assert iss_cred_data_dist_3(params, E_list, C_list, proof, custodian_list, group_generator)

        assert len(custodian_list) == n

        just_k_random_index = [1, 4, 7]

        decoded_list = []
        cust_pub_keys = []
        enc_shares = []

        for index in just_k_random_index:
            custodian_pub_key = custodian_list[index]
            cust_pub_keys.append(custodian_pub_key)
            enc_share = E_list[index]
            enc_shares.append(enc_share)
            # Here cusodian sees there key and answers. In this test instead we look up the private key.
            for (i, pub_k) in zip(range(len(pub_keys)), pub_keys):
                if pub_k == custodian_pub_key:
                    # Here we skip reading from list, since we only test restore
                    decoded_list.append(pvss.participant_decrypt_and_prove(params, priv_keys[i], enc_share))
                    break

        assert len(decoded_list) == len(just_k_random_index)

        answer = restore(params, decoded_list, [2, 5, 8], cust_pub_keys, enc_shares)
        assert answer is not None
        assert answer == my_pub_key
