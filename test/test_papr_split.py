from papr.user import User
from papr.issuer import Issuer
from papr.ecdsa import sign, verify
import pvss.pvss as pvss
from amac.credential_scheme import setup as setup_cmz
import pytest


class TestPaprSplit:

    def test_ledger(self):
        issuer = Issuer()
        params, y, iparams, sys_list, _, _, _ = issuer.setup(3, 4)
        assert len(issuer.sys_list.read()) == 2
        issuer.ledger_add(issuer.sys_list, "JAMAN")
        assert len(sys_list.read()) == 3

    def helper_enroll(self, id, issuer, user):
        """
        Complete Enrollment procedure. Inputs:
        id: real identity, i_sk: issuer's secret key for CMZ,
        x_sign: issuer's secret signature key, user_list: the list of users (ID: pub_ID) as described in PAPR.
        """
        id, pub_id, (u_sk, u_pk, c, pi_prepare_obtain) = user.req_enroll_1(id)
        ret = issuer.iss_enroll(u_pk['h'], c, pi_prepare_obtain, id, pub_id)
        if ret is not None:
            s_pub_id, u, e_u_prime, pi_issue, biparams = ret
            t_id = user.req_enroll_2(u_sk, u, e_u_prime, pi_issue, biparams, u_pk['h'], c)
            return t_id, s_pub_id, pub_id
        print("user already exists")
        return None

    def test_enroll(self):
        issuer = Issuer()
        id = "Ettan"
        params, (y_sign, y_encr), iparams, _, user_list, _, _ = issuer.setup(3, 10)
        user = User(params, iparams, y_sign, y_encr, 3, 10)
        ret = self.helper_enroll(id, issuer, user)
        assert ret is not None
        _, (r, s), pub_id = ret
        print(f"user_list.peek():   {user_list.peek()}\n")
        assert user_list.has("Ettan", 0)
        (G, p, g0, _) = params
        assert verify(G, p, g0, r, s, y_sign, [(id, pub_id)])

    def test_eq_id(self):
        issuer = Issuer()
        id = "Bertrand Russel"
        params, (_, _), iparams, _, user_list, _, _ = issuer.setup(3, 10)
        user = User(params, iparams, _, _, 3, 10)
        ret = self.helper_enroll(id, issuer, user)
        assert ret is not None
        t_id, _, _ = ret
        (u, cl, _), _, z = user.anon_auth(t_id)
        C_list, h = self.helper_data_dist_to_get_h(3, 10, params, user, issuer)
        c0 = C_list[0]
        y, c, gamma = user.eq_id(u, h, z, cl, c0)
        assert issuer.eq_id(u, h, y, c, gamma, cl, c0)

    def helper_data_dist_to_get_h(self, k, n, params, user, issuer):
        priv_keys = []
        pub_keys = []
        for _ in range(n*2):
            (x_i, y_i) = pvss.helper_generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)
        pub_cred = user.cred_sign_1()
        _ = user.data_dist_1()
        issuer_random = issuer.data_dist_1(pub_cred)
        _, _, C_list, _, group_generator = user.data_dist_2(issuer_random, pub_keys)
        return C_list, group_generator

    def test_data_distrubution(self):
        (k, n) = (3, 10)
        issuer = Issuer()
        params, (y_sign, y_encr), iparams, _, _, _, _ = issuer.setup(k, n)
        priv_keys = []
        pub_keys = []
        for _ in range(n*2):
            (x_i, y_i) = pvss.helper_generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        user = User(params, iparams, y_sign, y_encr, k, n)
        user.req_enroll_1('This is just here so that priv_id is generated')

        pub_cred = user.cred_sign_1()
        requester_commit = user.data_dist_1()
        issuer_random = issuer.data_dist_1(pub_cred)
        requester_random, E_list, C_list, proof, group_generator = user.data_dist_2(issuer_random, pub_keys)

        custodian_list = issuer.data_dist_2(requester_commit, requester_random, pub_keys, E_list, C_list, proof, group_generator, pub_cred)
        assert custodian_list is not None

    def test_full(self):
        (k, n) = (3, 10)
        issuer = Issuer()

        # Bootstrap
        issuer, sys_list, user_list, cred_list, rev_list, users, pub_creds, pub_ids = self.bootstrap_procedure(k, n, issuer)

        # Select one user for testing
        user = users[0]
        pub_cred = pub_creds[0]
        pub_id = pub_ids[0]

        # User authentication:
        m = issuer.ver_cred_1()
        sigma_m, pub_cred_new, sigma_pub_cred = user.show_cred_1(m)
        assert issuer.ver_cred_2(sigma_m, pub_cred_new, sigma_pub_cred, m)

        # Reconstruction
        answer = self.revoke_procedure(issuer, rev_list, users, pub_cred)

        assert answer is not None
        assert answer == pub_id

    def helper_revoke(self, rev_list, pub_cred, indexes, params, priv_keys, issuer):
        revocation_list = rev_list.read()
        for rev_obj in revocation_list:
            if rev_obj[0] == pub_cred:
                (custodians, escrow_shares) = rev_obj[1]

                decoded_list = []
                cust_pub_keys = []
                enc_shares = []
                for index in indexes:
                    cust_pub_keys.append(custodians[index])
                    enc_shares.append(escrow_shares[index])
                    # Here custodian sees there key and answers. In this test instead we look up the private key.
                    for (i, pub_k) in zip(range(len(custodians)), custodians):
                        if pub_k == custodians[index]:
                            # Here we skip reading from list, since we only test restore
                            decoded_list.append(pvss.participant_decrypt_and_prove(params, priv_keys[i], escrow_shares[index]))
                            break
                import pdb
                pdb.set_trace()
                return issuer.restore(decoded_list, indexes, cust_pub_keys, enc_shares)
            break

        # Else:
        assert False, "pub_cred not revoked"

    def test_sign_verify(self):
        params = setup_cmz(1)
        (G, p, g0, _) = params

        x_sign = p.random()
        y_sign = x_sign * g0
        m = p.random()
        r, s = sign(p, g0, x_sign, [m])
        assert verify(G, p, g0, r, s, y_sign, [m])

    @pytest.mark.run_these_please
    def test_bootstrap(self):
        (k, n) = (3, 10)
        issuer = Issuer()
        params, (y_sign, y_encr), iparams, _, user_list, cred_list, rev_list = issuer.setup(k, n)
        (G, p, g0, _) = params
        bootstrap_users = []
        pub_creds_encr = []

        # generate pub_creds for each user
        for i in range(n+1):
            user = User(params, iparams, y_sign, y_encr, k, n)
            t_id, sigma_pub_id, pub_id = self.helper_enroll(str(i), issuer, user)
            assert verify(G, p, g0, *sigma_pub_id, y_sign, [(str(i), pub_id)])
            pub_cred = user.cred_sign_1()
            bootstrap_users.append({"user": user, "t_id": t_id, "pub_id": pub_id, "pub_cred": pub_cred})
            pub_creds_encr.append(pub_cred[0])

        # distribute pub_id for each user
        for dict_elem in bootstrap_users:
            user = dict_elem['user']
            t_id = dict_elem['t_id']
            pub_id = dict_elem['pub_id']
            pub_cred = dict_elem['pub_cred']

            requester_commit = user.data_dist_1()
            issuer_random = issuer.data_dist_1(pub_cred)
            requester_random, E_list, C_list, proof, group_generator = user.data_dist_2(issuer_random, pub_creds_encr)
            custodian_list = issuer.data_dist_2(requester_commit, requester_random, pub_creds_encr, E_list, C_list, proof, group_generator, pub_cred)

            assert custodian_list is not None
            assert pub_cred[0] not in custodian_list  # Verify that we are not a custodian of ourself

            # Anonymous auth:
            sigma, pi_show, z = user.anon_auth(t_id)
            assert issuer.anon_auth(sigma, pi_show)
            (u2, cl, _) = sigma

            # Proof of eq id:
            y, c, gamma = user.eq_id(u2, group_generator, z, cl, C_list[0])
            assert issuer.eq_id(u2, group_generator, y, c, gamma, cl, C_list[0])
            # Fixme: message to user so that it knows that it can submit credentails (anonimously)

            # Cred signing:
            sigma_pub_cred = issuer.cred_sign(pub_cred)
            assert user.cred_sign_2(sigma_pub_cred)
            (sigma_y_e, sigma_y_s) = sigma_pub_cred
            assert verify(G, p, g0, *sigma_y_e, y_sign, [pub_cred[0]])
            assert verify(G, p, g0, *sigma_y_s, y_sign, [pub_cred[1]])
            assert cred_list.peek() == pub_cred

            # User authentication:
            m = issuer.ver_cred_1()
            sigma_m, pub_cred_new, sigma_pub_cred = user.show_cred_1(m)
            assert issuer.ver_cred_2(sigma_m, pub_cred_new, sigma_pub_cred, m)

        pub_cred = bootstrap_users[0]['pub_cred']
        issuer.get_rev_data(pub_cred)

        assert rev_list.peek() is not None

        # Users polling rev_list and answering if applicable
        for dict_elem in bootstrap_users:
            user = dict_elem['user']
            pub_cred = dict_elem['pub_cred']
            responses = user.curl_rev_list(rev_list)
            for (pub_cred_revoked, (pub_cred_answerer, response)) in responses:
                issuer.get_response(pub_cred_revoked, pub_cred_answerer, response)

        answer = issuer.restore(bootstrap_users[0]['pub_cred'])
        assert answer is not None
        assert answer == bootstrap_users[0]['pub_id']

        # [x] Enc shares empty. : Fixed
        # [x] Index repeat sometimes?
        # [ ] verify correct decryption fail, called in issuer.restore

    def bootstrap_procedure(self, k, n, issuer):
        params, (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list = issuer.setup(k, n)
        (G, p, g0, _) = params
        bootstrap_users = []
        pub_creds_encr = []

        users = []
        pub_ids = []
        pub_creds = []

        # generate pub_creds for each user
        for i in range(n+1):
            user = User(params, iparams, y_sign, y_encr, k, n)
            t_id, sigma_pub_id, pub_id = self.helper_enroll(str(i), issuer, user)
            assert verify(G, p, g0, *sigma_pub_id, y_sign, [(str(i), pub_id)])
            pub_cred = user.cred_sign_1()
            bootstrap_users.append({"user": user, "t_id": t_id, "pub_id": pub_id, "pub_cred": pub_cred})
            pub_creds_encr.append(pub_cred[0])

            # For external tests
            users.append(user)
            pub_ids.append(pub_id)
            pub_creds.append(pub_cred)

        # distribute pub_id for each user
        for dict_elem in bootstrap_users:
            user = dict_elem['user']
            t_id = dict_elem['t_id']
            pub_id = dict_elem['pub_id']
            pub_cred = dict_elem['pub_cred']

            requester_commit = user.data_dist_1()
            issuer_random = issuer.data_dist_1(pub_cred)
            requester_random, E_list, C_list, proof, group_generator = user.data_dist_2(issuer_random, pub_creds_encr)
            custodian_list = issuer.data_dist_2(requester_commit, requester_random, pub_creds_encr, E_list, C_list, proof, group_generator, pub_cred)

            assert custodian_list is not None
            assert pub_cred[0] not in custodian_list  # Verify that we are not a custodian of ourself

            # Anonymous auth:
            sigma, pi_show, z = user.anon_auth(t_id)
            assert issuer.anon_auth(sigma, pi_show)
            (u2, cl, _) = sigma

            # Proof of eq id:
            y, c, gamma = user.eq_id(u2, group_generator, z, cl, C_list[0])
            assert issuer.eq_id(u2, group_generator, y, c, gamma, cl, C_list[0])
            # Fixme: message to user so that it knows that it can submit credentails (anonymously)

            # Cred signing:
            sigma_pub_cred = issuer.cred_sign(pub_cred)
            assert user.cred_sign_2(sigma_pub_cred)
            (sigma_y_e, sigma_y_s) = sigma_pub_cred
            assert verify(G, p, g0, *sigma_y_e, y_sign, [pub_cred[0]])
            assert verify(G, p, g0, *sigma_y_s, y_sign, [pub_cred[1]])

        return issuer, sys_list, user_list, cred_list, rev_list, users, pub_creds, pub_ids

    def revoke_procedure(self, issuer, rev_list, users, pub_cred_to_revoke):

        issuer.get_rev_data(pub_cred_to_revoke)

        assert rev_list.peek() is not None

        # Users polling rev_list and answering if applicable
        for user in users:
            # user = dict_elem['user']
            # pub_cred_to_revoke = dict_elem['pub_cred']
            responses = user.curl_rev_list(rev_list)
            for (pub_cred_revoked, (pub_cred_answerer, response)) in responses:
                issuer.get_response(pub_cred_revoked, pub_cred_answerer, response)

        # answer = issuer.restore(bootstrap_users[0]['pub_cred'])
        # assert answer is not None
        # assert answer == bootstrap_users[0]['pub_id']

        return issuer.restore(pub_cred_to_revoke)
