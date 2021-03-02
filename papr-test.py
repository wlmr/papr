
from papr.papr_procedures import setup
from papr.papr_procedures import enroll
if __name__ == "__main__":
    params, (x_sign, x_encr), (y_sign, y_encr), (iparams, i_sk) = setup(3, 10)
    t_id, sigma = enroll(params, "Wilmer Nilsson", iparams, i_sk, x_sign)
    print("T(ID): ", t_id)
    print("Signature: ", sigma)
