from papr.user import User
from papr.issuer import Issuer
from papr.ecdsa import sign, verify
import pvss.pvss as pvss
from amac.credential_scheme import setup as setup_cmz
# import pytest


class TestPaprSplit:

    def test_ledger(self):
        issuer = Issuer()
        ret = issuer.setup(3, 4)
        assert len(issuer.sys_list.read()) == 2


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

    def test_restore(self):
        (k, n) = (3, 10)
        issuer = Issuer()
        params, (y_sign, y_encr), iparams, _, _, _, _ = issuer.setup(k, n)
        priv_keys = []
        pub_keys = []

        for i in range(n*2):
            (x_i, y_i) = pvss.helper_generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        user = User(params, iparams, y_sign, y_encr, k, n)
        _, my_pub_key, _ = user.req_enroll_1('This is just here so that priv_id is generated')
        pub_cred = user.cred_sign_1()
        requester_commit = user.data_dist_1()
        issuer_random = issuer.data_dist_1(pub_cred)

        requester_random, E_list, C_list, proof, group_generator = user.data_dist_2(issuer_random, pub_keys)

        custodian_list = issuer.data_dist_2(requester_commit, requester_random, pub_keys, E_list, C_list, proof, group_generator, pub_cred)
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

        answer = issuer.restore(decoded_list, just_k_random_index, cust_pub_keys, enc_shares)
        assert answer is not None
        assert answer == my_pub_key

    def test_full(self):
        (k, n) = (3, 10)
        issuer = Issuer()
        params, (y_sign, y_encr), iparams, _, _, cred_list, rev_list = issuer.setup(k, n)

        # Fake other users pub/priv keys
        (G, p, g0, _) = params
        priv_keys = []
        pub_keys = []
        for _ in range(n*2):
            (x_i, y_i) = pvss.helper_generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        # Note: take from L_sys instead??
        user = User(params, iparams, y_sign, y_encr, k, n)
        id = "Id text"

        # User Enrollment:
        _, pub_id, (u_sk, u_pk, c, pi_prepare_obtain) = user.req_enroll_1(id)
        ret = issuer.iss_enroll(u_pk['h'], c, pi_prepare_obtain, id, pub_id)
        if ret is not None:
            _, u, e_u_prime, pi_issue, biparams = ret
            t_id = user.req_enroll_2(u_sk, u, e_u_prime, pi_issue, biparams, u_pk['h'], c)
        assert ret is not None  # : "user already exists"
        
        # Credential Issuance
        pub_cred = user.cred_sign_1()
        
        # Anonymous authentication:
        sigma, pi_show, z = user.anon_auth(t_id)
        assert issuer.anon_auth(sigma, pi_show)

        # Data distribution
        requester_commit = user.data_dist_1()
        issuer_random = issuer.data_dist_1(pub_cred)
        requester_random, E_list, C_list, proof, group_generator = user.data_dist_2(issuer_random, pub_keys)
        custodian_list = issuer.data_dist_2(requester_commit, requester_random, pub_keys, E_list, C_list, proof, group_generator, pub_cred)
        assert custodian_list is not None

        # Proof of equal identity:
        (u2, cl, _) = sigma
        y, c, gamma = user.eq_id(u2, group_generator, z, cl, C_list[0])
        eq_id_proof_is_correct = issuer.eq_id(u2, group_generator, y, c, gamma, cl, C_list[0])
        assert eq_id_proof_is_correct

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

        # Reconstruction
        issuer.get_rev_data(pub_cred)

        assert rev_list.peek() == (pub_cred, (E_list, custodian_list))

        # In this testcase all users have the ability to answer. Here we select 3 random users 
        just_k_random_index = [1, 4, 7]

        decoded_list = []
        cust_pub_keys = []
        enc_shares = []

        for index in just_k_random_index:
            custodian_pub_key = custodian_list[index]
            cust_pub_keys.append(custodian_pub_key)
            enc_share = E_list[index]
            enc_shares.append(enc_share)
            # Here custodian sees there key and answers. In this test instead we look up the private key.
            for (i, pub_k) in zip(range(len(pub_keys)), pub_keys):
                if pub_k == custodian_pub_key:
                    # Here we skip reading from list, since we only test restore
                    decoded_list.append(pvss.participant_decrypt_and_prove(params, priv_keys[i], enc_share))
                    break

        assert len(decoded_list) == len(just_k_random_index)

        answer = issuer.restore(decoded_list, just_k_random_index, cust_pub_keys, enc_shares)
        assert answer is not None
        assert answer == pub_id

    def helper_revoke(self, rev_list, pub_cred, indexes, params):
        revocation_list = rev_list.read()
        for rev_obj in revocation_list:
            if rev_obj[0] == pub_cred:
                (custodians, escrow_shares) = rev_obj[1]
                decoded_list = []
                for index in indexes:
                    # Here custodian sees their key and answers. In this test instead we look up the private key.
                    for (i, pub_k) in zip(range(len(custodians)), custodians):
                        if pub_k == custodians[index]:
                            # Here we skip reading from list, since we only test restore
                            decoded_list.append(pvss.participant_decrypt_and_prove(params, priv_keys[i], escrow_shares))
                            break
                return issuer.restore(decoded_list, indexes, custodians, escrow_shares)
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

    def test_bootstrap(self):
        (k, n) = (3, 10)
        issuer = Issuer()
        params, (y_sign, y_encr), iparams, _, user_list, _, _ = issuer.setup(k, n)
        (G, p, g0, _) = params
        bootstrap_users = []
        pub_creds_encr = []
        priv_rev_tuple = []
        # pub_ids = []
        for i in range(n):
            user = User(params, iparams, y_sign, y_encr, k, n)
            t_id, sigma_pub_id, pub_id = self.helper_enroll(str(i), issuer, user)
            assert verify(G, p, g0, *sigma_pub_id, y_sign, [(str(i), pub_id)])
            pub_cred = user.cred_sign_1()
            bootstrap_users.append({"user": user, "t_id": t_id, "pub_id": pub_id, "pub_cred": pub_cred})
            pub_creds_encr.append(pub_cred[0])

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

            # Anonimous auth:
            sigma, pi_show, z = user.anon_auth(t_id)
            assert issuer.anon_auth(sigma, pi_show)
            (u2, cl, _) = sigma

            # Proof of eq id:
            y, c, gamma = user.eq_id(u2, group_generator, z, cl, C_list[0])
            assert issuer.eq_id(u2, group_generator, y, c, gamma, cl, C_list[0])
            # Fixme: message to user so that it knows that it can submit credentails (anonimously)

            priv_rev_tuple.append((pub_cred, E_list, custodian_list))

        (pub_cred, E_list, cust_pub_keys) = priv_rev_tuple[0]

        decoded_list = []

        indexes = []

        for (enc_share, cust_pub_key) in zip(E_list, cust_pub_keys):
            # Here cusodian sees there key and answers. In this test instead we look up the private key.
            for (i, pub_k) in zip(range(len(pub_creds_encr)), pub_creds_encr):
                if pub_k == cust_pub_key:
                    # Here we skip reading from list, since we only test restore
                    user = bootstrap_users[i]['user']
                    decoded_list.append(user.respond(enc_share))
                    indexes.append(i+1)

        answer = issuer.restore(decoded_list[:3], [0, 1, 2], cust_pub_keys[:3], E_list[:3])
        assert answer is not None
        assert answer == bootstrap_users[0]['pub_id']

        # Test another order and other numbers for decryption.
        answer = issuer.restore([decoded_list[0], decoded_list[3], decoded_list[1]], [0, 3, 1], [
                                cust_pub_keys[0], cust_pub_keys[3], cust_pub_keys[1]], [E_list[0], E_list[3], E_list[1]])
        assert answer is not None
        assert answer == bootstrap_users[0]['pub_id']

        # [x] Enc shares empty. : Fixed
        # [ ] Index repeat sometimes?
        # [ ] verify correct decryption fail, called in issuer.restore
