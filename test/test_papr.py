
from papr.papr_procedures import data_distrubution_I_2, data_distrubution_I_1, \
    data_distrubution_U_2, data_distrubution_U_1, data_distrubution_select, setup, enroll
from papr.ecdsa import verify
import pvss.pvss as pvss


class TestPapr:

    def test_papr(self):
        id = "Wilmer Nilsson"
        params, (x_sign, x_encr), (y_sign, y_encr), (iparams, i_sk), sys_list, user_list, cred_list, rev_list, res_list = setup(3, 10)
        # user_list.add(params, G.generator(), id, sign(params, x_sign, G.generator().get_affine()[0]))
        ret = enroll(params, id, iparams, i_sk, x_sign, user_list)
        if ret is not None:
            t_id, (r, s), priv_id, pub_id, user_list = ret
            print(f"user_list.peek():   {user_list.peek()}\n")
            assert user_list.has("Wilmer Nilsson", 0)
            print("verified signature!" if verify(params, r, s, y_sign, pub_id.get_affine()[0]) else "signature verification failed")

    def test_data_distrubution(self):
        (k, n) = (3, 10)

        params, (x_sign, x_encr), (y_sign, y_encr), (iparams, i_sk), sys_list, user_list, cred_list, rev_list, res_list = setup(k, n)

        (_, p, _, _) = params
        priv_keys = []
        pub_keys = []
        for i in range(8):
            (x_i, y_i) = pvss.generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        (my_priv_key, my_pub_key) = pvss.generate_key_pair(params)

        r1 = data_distrubution_U_1(params)
        r2 = data_distrubution_I_1(params)

        selected_pub_keys = data_distrubution_select(pub_keys, r1, r2, 4, p)
        E_list, C_list, proof, group_generator = data_distrubution_U_2(my_priv_key, selected_pub_keys, 3, 4, params)

        assert data_distrubution_I_2(E_list, C_list, proof, selected_pub_keys, group_generator, p)
