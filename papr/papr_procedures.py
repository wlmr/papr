from amac.credential_scheme import setup as setup_cmz, cred_keygen as cred_keygen_cmz
from amac.credential_scheme import prepare_blind_obtain as prepare_blind_obtain_cmz
from amac.credential_scheme import blind_issue as blind_issue_cmz
from amac.credential_scheme import blind_obtain as blind_obtain_cmz
""" from amac.credential_scheme import blind_show as blind_show_cmz
from amac.credential_scheme import show_verify as show_verify """
from papr.ecdsa import sign
from papr.papr_list import Papr_list


def setup(k, n):
    """
    k, n defines the PVSS-threshold scheme
    Generates the CRS, and all the system values that it consists of.

    TODO: [ ] publish return value to Lsys.
    """
    params = setup_cmz(1)
    (_, p, g0, g1) = params
    (x_sign, x_encr) = (p.random(), p.random())
    (y_sign, y_encr) = (x_sign * g0, x_encr * g0)
    (iparams, i_sk) = cred_keygen_cmz(params)
    crs = ",".join([str(elem) for elem in [p.repr(), g0, g1, n, k, iparams['Cx0']]])
    i_pk = ",".join([str(x) for x in [y_sign, y_encr]])
    user_list, sys_list = Papr_list(y_sign), Papr_list(y_sign)
    sys_list.add(params, crs, sign(params, x_sign, [crs]))
    sys_list.add(params, i_pk, sign(params, x_sign, [i_pk]))
    return params, (x_sign, x_encr), (y_sign, y_encr), (iparams, i_sk), sys_list, user_list


def req_enroll_1(params, id):
    """
    Generates the secret key l and returns the encrypted l along with a zkp of
    l and r (r is used in elgamal-encryption).
    Returns the tuple (id, l, g0^l, ElGamal-SK, ElGamal-PK, ElGamal-ciphertext, ZKP)
    """
    (_, p, g0, _) = params
    priv_id = p.random()  # a.k.a. l
    pub_id = priv_id * g0
    return id, priv_id, pub_id, prepare_blind_obtain_cmz(params, priv_id)


def iss_enroll(params, iparams, i_sk, gamma, ciphertext, pi_prepare_obtain, id, pub_id, x_sign, user_list):
    """
    Returns the elgamal-encrypted credential T(ID) that only the user can
    decrypt and use, as well as a signature on the pub_id
    """
    if not user_list.has(id, 0):
        sigma_pub_id = sign(params, x_sign, [id, pub_id])
        if user_list.add(params, (id, pub_id), sigma_pub_id):
            return sigma_pub_id, blind_issue_cmz(params, iparams, i_sk, gamma, ciphertext, pi_prepare_obtain), user_list
    return None


def req_enroll_2(params, iparams, u_sk, u, e_u_prime, pi_issue, biparams, gamma, ciphertext):
    """
    Returns the T(ID), if all goes well.
    """
    return blind_obtain_cmz(params, iparams, u_sk, u, e_u_prime, pi_issue, biparams,
                            gamma, ciphertext)


def enroll(params, id, iparams, i_sk, x_sign, user_list):
    """
    Complete Enrollment procedure. Inputs:
    id: real identity, i_sk: issuer's secret key for CMZ,
    x_sign: issuer's secret signature key, user_list: the list of users (ID: pub_ID) as described in PAPR.
    """
    id, priv_id, pub_id, (u_sk, u_pk, c, pi_prepare_obtain) = req_enroll_1(params, id)
    ret = iss_enroll(params, iparams, i_sk, u_pk['h'], c, pi_prepare_obtain, id, pub_id, x_sign, user_list)
    if ret is not None:
        s_pub_id, (u, e_u_prime, pi_issue, biparams), user_list = ret
        t_id = req_enroll_2(params, iparams, u_sk, u, e_u_prime, pi_issue, biparams, u_pk['h'], c)
        return t_id, s_pub_id, priv_id, pub_id, user_list
    print("user already exists")
    return None
