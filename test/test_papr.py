
from papr.papr_procedures import data_distrubution_I_2, data_distrubution_U_2
from papr.papr_procedures import data_distrubution_random_commit, data_distrubution_select
from papr.papr_procedures import data_distrubution_verify_commit, setup, enroll
from papr.papr_procedures import req_cred_eq_id, iss_cred_eq_id
from papr.papr_procedures import req_cred_anon_auth  # temporary until cred is fully working
from papr.ecdsa import verify
import pvss.pvss as pvss


class TestPapr:

    def test_enroll(self):
        id = "Wilmer Nilsson"
        params, (x_sign, x_encr), (y_sign, y_encr), (iparams, i_sk), sys_list, user_list, cred_list, rev_list, res_list = setup(3, 10)
        ret = enroll(params, id, iparams, i_sk, x_sign, user_list)
        assert ret is not None
        t_id, (r, s), priv_id, pub_id, user_list = ret
        print(f"user_list.peek():   {user_list.peek()}\n")
        assert user_list.has("Wilmer Nilsson", 0)
        assert verify(params, r, s, y_sign, (id, pub_id))

    def test_eq_id(self):
        id = "Wilmer Nilsson"
        params, (x_sign, x_encr), (y_sign, y_encr), (iparams, i_sk), sys_list, user_list, cred_list, rev_list, res_list = setup(3, 10)
        (_, p, g0, g1) = params
        ret = enroll(params, id, iparams, i_sk, x_sign, user_list)
        assert ret is not None
        t_id, (r, s), priv_id, pub_id, user_list = ret
        (u, cl, cu_prime), zkp, z = req_cred_anon_auth(params, iparams, t_id, priv_id)
        h = p.random() * g0
        c0 = priv_id * h
        y, c, gamma, cl, c0 = req_cred_eq_id(params, u, h, priv_id, z, cl, c0)
        assert iss_cred_eq_id(params, u, h, y, c, gamma, cl, c0)

    def test_data_distrubution(self):
        (k, n) = (3, 10)

        params, (x_sign, x_encr), (y_sign, y_encr), (iparams, i_sk), sys_list, user_list, cred_list, rev_list, res_list = setup(k, n)

        (_, p, _, _) = params
        priv_keys = []
        pub_keys = []
        for i in range(n*2):
            (x_i, y_i) = pvss.generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        (my_priv_key, my_pub_key) = pvss.generate_key_pair(params)

        # r1 = data_distrubution_U_1(params)
        # r2 = data_distrubution_I_1(params)

        (c1, r1) = data_distrubution_random_commit(params)
        (c2, r2) = data_distrubution_random_commit(params)
        # Both publishes their commits. When they recive the other ones commit they send their random value.
        # and verifyes that the commit and random value they recived are correct.
        assert data_distrubution_verify_commit(params, c1, r1)
        assert data_distrubution_verify_commit(params, c2, r2)

        selected_pub_keys = data_distrubution_select(pub_keys, r1, r2, n, p)
        E_list, C_list, proof, group_generator = data_distrubution_U_2(my_priv_key, selected_pub_keys, k, n, params)

        assert data_distrubution_I_2(E_list, C_list, proof, selected_pub_keys, group_generator, p)
