from papr.papr_user import User
from papr.papr_issuer import Issuer
from papr.ecdsa import sign, verify
import pvss.pvss as pvss
# from petlib.pack import encode, decode
from amac.credential_scheme import setup as setup_cmz


class TestPaprSplit:

    def helper_enroll(self, id, user_list, issuer, user):
        """
        Complete Enrollment procedure. Inputs:
        id: real identity, i_sk: issuer's secret key for CMZ,
        x_sign: issuer's secret signature key, user_list: the list of users (ID: pub_ID) as described in PAPR.
        """
        id, pub_id, (u_sk, u_pk, c, pi_prepare_obtain) = user.req_enroll_1(id)
        ret = issuer.iss_enroll(u_pk['h'], c, pi_prepare_obtain, id, pub_id, user_list)
        if ret is not None:
            s_pub_id, (u, e_u_prime, pi_issue, biparams) = ret
            t_id = user.req_enroll_2(u_sk, u, e_u_prime, pi_issue, biparams, u_pk['h'], c)
            return t_id, s_pub_id, pub_id
        print("user already exists")
        return None

    def test_enroll(self):
        issuer = Issuer()
        id = "Wilmer Nilsson"
        (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list, res_list = issuer.setup(3, 10)
        user = User(issuer.get_params(), iparams, y_sign, y_encr, 3, 10)
        ret = self.helper_enroll(id, user_list, issuer, user)
        assert ret is not None
        t_id, (r, s), pub_id = ret
        print(f"user_list.peek():   {user_list.peek()}\n")
        assert user_list.has("Wilmer Nilsson", 0)
        (G, p, g0, g1) = issuer.get_params()
        assert verify(G, p, g0, r, s, y_sign, (id, pub_id))

    def test_eq_id(self):
        issuer = Issuer()
        id = "Wilmer Nilsson"
        (_, _), iparams, _, user_list, _, _, _ = issuer.setup(3, 10)
        user = User(issuer.get_params(), iparams, _, _, 3, 10)
        ret = self.helper_enroll(id, user_list, issuer, user)
        assert ret is not None
        t_id, _, _ = ret
        (u, cl, _), _, z = user.req_cred_anon_auth(t_id)
        C_list, h = self.helper_data_dist_to_get_h(3, 10, issuer.get_params(), user, issuer)
        c0 = C_list[0]

        y, c, gamma = user.req_cred_eq_id(u, h, z, cl, c0)
        assert issuer.iss_cred_eq_id(u, h, y, c, gamma, cl, c0)

    def helper_data_dist_to_get_h(self, k, n, params, user, issuer):
        priv_keys = []
        pub_keys = []
        for i in range(n*2):
            (x_i, y_i) = pvss.generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        _ = user.req_cred_data_dist_1()
        issuer_random = issuer.iss_cred_data_dist_1()
        _, _, C_list, _, group_generator = user.req_cred_data_dist_2(issuer_random, pub_keys)
        return C_list, group_generator

    def test_data_distrubution(self):
        (k, n) = (3, 10)
        issuer = Issuer()
        (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list, res_list = issuer.setup(k, n)

        params = issuer.get_params()
        (_, p, _, _) = params
        priv_keys = []
        pub_keys = []
        for i in range(n*2):
            (x_i, y_i) = pvss.generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        user = User(issuer.get_params(), iparams, y_sign, y_encr, k, n)
        user.req_enroll_1('This is just here so that priv_id is generated')

        requester_commit = user.req_cred_data_dist_1()
        issuer_random = issuer.iss_cred_data_dist_1()
        requester_random, E_list, C_list, proof, group_generator = user.req_cred_data_dist_2(issuer_random, pub_keys)

        custodian_list = issuer.iss_cred_data_dist_2(requester_commit, requester_random, pub_keys, E_list, C_list, proof, group_generator)
        assert custodian_list is not None

    def test_restore(self):
        (k, n) = (3, 10)
        issuer = Issuer()
        (y_sign, y_encr), iparams, _, _, _, _, _ = issuer.setup(k, n)

        params = issuer.get_params()
        (_, p, _, _) = params
        priv_keys = []
        pub_keys = []
        for i in range(n*2):
            (x_i, y_i) = pvss.generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        user = User(issuer.get_params(), iparams, y_sign, y_encr, k, n)
        _, my_pub_key, _ = user.req_enroll_1('This is just here so that priv_id is generated')

        requester_commit = user.req_cred_data_dist_1()
        issuer_random = issuer.iss_cred_data_dist_1()

        requester_random, E_list, C_list, proof, group_generator = user.req_cred_data_dist_2(issuer_random, pub_keys)

        custodian_list = issuer.iss_cred_data_dist_2(requester_commit, requester_random, pub_keys, E_list, C_list, proof, group_generator)
        assert custodian_list is not None

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

        answer = issuer.restore(decoded_list, [2, 5, 8], cust_pub_keys, enc_shares)
        assert answer is not None
        assert answer == my_pub_key

    def test_full(self):
        (k, n) = (3, 10)
        issuer = Issuer()
        (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list, res_list = issuer.setup(k, n)

        params = issuer.get_params()
        priv_keys = []
        pub_keys = []
        for i in range(n*2):
            (x_i, y_i) = pvss.generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        # Note: take from L_sys instead??
        user = User(issuer.get_params(), iparams, y_sign, y_encr, k, n)
        id = "Id text"

        # Enroll:
        _, pub_id, (u_sk, u_pk, c, pi_prepare_obtain) = user.req_enroll_1(id)
        ret = issuer.iss_enroll(u_pk['h'], c, pi_prepare_obtain, id, pub_id, user_list)
        if ret is not None:
            s_pub_id, (u, e_u_prime, pi_issue, biparams) = ret
            t_id = user.req_enroll_2(u_sk, u, e_u_prime, pi_issue, biparams, u_pk['h'], c)
        assert ret is not None  # : "user already exists"

        # Data dist
        requester_commit = user.req_cred_data_dist_1()
        issuer_random = issuer.iss_cred_data_dist_1()
        requester_random, E_list, C_list, proof, group_generator = user.req_cred_data_dist_2(issuer_random, pub_keys)
        custodian_list = issuer.iss_cred_data_dist_2(requester_commit, requester_random, pub_keys, E_list, C_list, proof, group_generator)
        assert custodian_list is not None

        # Anonimous auth:
        sigma, pi_show, z = user.req_cred_anon_auth(t_id)
        assert issuer.iss_cred_anon_auth(sigma, pi_show)

        (u2, cl, _) = sigma

        # Proof of eq id:
        y, c, gamma = user.req_cred_eq_id(u2, group_generator, z, cl, C_list[0])
        assert issuer.iss_cred_eq_id(u2, group_generator, y, c, gamma, cl, C_list[0])
        # Fixme message to user so that it knows that it can submit credentails (anonimously)

        pub_cred = user.req_cred_sign()
        signed_pub_cred = issuer.iss_cred_sign(pub_cred)

        assert cred_list.peek() == signed_pub_cred

        # Cred usage:
        m = issuer.ver_cred_1()
        (r, s) = user.show_cred_1(m)
        assert issuer.ver_cred_2(r, s, pub_cred, m)

        # Reconstruction
        issuer.get_rev_data(pub_cred)

        assert rev_list.peek() == pub_cred

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

        answer = issuer.restore(decoded_list, [2, 5, 8], cust_pub_keys, enc_shares)
        assert answer is not None
        assert answer == pub_id

    def test_encode_decode(self):
        (k, n) = (3, 10)
        issuer = Issuer()
        (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list, res_list = issuer.setup(k, n)

        params = issuer.get_params()
        (_, p, _, _) = params
        priv_keys = []
        pub_keys = []
        for i in range(n*2):
            (x_i, y_i) = pvss.generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        user = User(issuer.get_params(), iparams, y_sign, y_encr, k, n)
        id = "Id text"
        # Enroll:
        _, pub_id, (u_sk, u_pk, c, pi_prepare_obtain) = user.req_enroll_1(id)
        ret = issuer.iss_enroll(u_pk['h'], c, pi_prepare_obtain, id, pub_id, user_list)
        ret  # Just here to remove flake error.
        # assert decode(encode(ret)) == ret
        # assert decode(encode((((1, 2))))) == [[(1, 2)]]

    def test_encode_decode_list(self):
        (k, n) = (3, 10)
        issuer = Issuer()
        (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list, res_list = issuer.setup(k, n)

        params = issuer.get_params()
        (_, p, _, _) = params
        priv_keys = []
        pub_keys = []
        for i in range(n*2):
            (x_i, y_i) = pvss.generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        # Note: take from L_sys instead??
        user = User(issuer.get_params(), iparams, y_sign, y_encr, k, n)
        id = "Id text"
        # Enroll:
        _, pub_id, (u_sk, u_pk, c, pi_prepare_obtain) = user.req_enroll_1(id)
        ret = issuer.iss_enroll(u_pk['h'], c, pi_prepare_obtain, id, pub_id, user_list)
        if ret is not None:
            s_pub_id, (u, e_u_prime, pi_issue, biparams) = ret
            t_id = user.req_enroll_2(u_sk, u, e_u_prime, pi_issue, biparams, u_pk['h'], c)
        assert ret is not None  # : "user already exists"

        # Data dist
        requester_commit = user.req_cred_data_dist_1()
        issuer_random = issuer.iss_cred_data_dist_1()
        requester_random, E_list, C_list, proof, group_generator = user.req_cred_data_dist_2(issuer_random, pub_keys)
        custodian_list = issuer.iss_cred_data_dist_2(requester_commit, requester_random, pub_keys, E_list, C_list, proof, group_generator)
        assert custodian_list is not None

        # Anonimous auth:
        sigma, pi_show, z = user.req_cred_anon_auth(t_id)
        assert issuer.iss_cred_anon_auth(sigma, pi_show)
        (u2, cl, _) = sigma

        # Proof of eq id:
        y, c, gamma = user.req_cred_eq_id(u2, group_generator, z, cl, C_list[0])
        assert issuer.iss_cred_eq_id(u2, group_generator, y, c, gamma, cl, C_list[0])
        # Fixme: message to user so that it knows that it can submit credentails (anonimously)

        PubCred = user.req_cred_sign()
        signed_pub_cred = issuer.iss_cred_sign(PubCred)

        assert cred_list.peek() == signed_pub_cred
        # encode(cred_list)
        # assert cred_list == decode(encode(cred_list))

    def test_sign_verify(self):
        params = setup_cmz(1)
        (G, p, g0, _) = params

        x_sign = p.random()
        y_sign = x_sign * g0
        m = p.random()
        r, s = sign(p, g0, x_sign, [m])
        assert verify(G, p, g0, r, s, y_sign, [m])
