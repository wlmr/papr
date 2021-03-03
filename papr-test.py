
from papr.papr_procedures import setup
from papr.papr_procedures import enroll
from papr.ecdsa import verify

if __name__ == "__main__":
    params, (x_sign, x_encr), (y_sign, y_encr), (iparams, i_sk) = setup(3, 10)
    (G, p, g, h) = params
    t_id, (r, s), pub_id = enroll(params, "Wilmer Nilsson", iparams, i_sk, x_sign)
    print("T(ID): ", t_id)
    print("Signature: ", (r, s))
    print("verified signature!" if verify(params, r, s, y_sign, pub_id.get_affine()[0]) else "signature verification failed")
