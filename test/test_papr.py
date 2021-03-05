
from papr.papr_procedures import setup, enroll
from papr.ecdsa import verify


class TestPapr:

    def test_papr(self):
        id = "Wilmer Nilsson"
        params, (x_sign, x_encr), (y_sign, y_encr), (iparams, i_sk), sys_list, user_list = setup(3, 10)
        # user_list.add(params, G.generator(), id, sign(params, x_sign, G.generator().get_affine()[0]))
        ret = enroll(params, id, iparams, i_sk, x_sign, user_list)
        if ret is not None:
            t_id, (r, s), priv_id, pub_id, user_list = ret
            print(f"user_list.peek():   {user_list.peek()}\n")
            assert user_list.has("Wilmer Nilsson", 0)
            print("verified signature!" if verify(params, r, s, y_sign, pub_id.get_affine()[0]) else "signature verification failed")
