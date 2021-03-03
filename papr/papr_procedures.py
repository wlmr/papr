from amac.credential_scheme import setup as setup_cmz, cred_keygen as cred_keygen_cmz
from amac.credential_scheme import prepare_blind_obtain as prepare_blind_obtain_cmz
from amac.credential_scheme import blind_issue as blind_issue_cmz
from amac.credential_scheme import blind_obtain as blind_obtain_cmz
""" from amac.credential_scheme import blind_show as blind_show_cmz
from amac.credential_scheme import show_verify as show_verify """
from papr.ecdsa import sign


def setup(k, n):
    """
    k, n defines the PVSS-threshold scheme
    Generates the CRS, and all the system values that it consists of.

    TODO: [ ] publish return value to Lsys.
    """
    params = setup_cmz(1)
    (G, p, g0, g1) = params
    (x_sign, x_encr) = (p.random(), p.random())
    (y_sign, y_encr) = (x_sign * g0, x_encr * g0)
    (iparams, i_sk) = cred_keygen_cmz(params)
    # crs = ",".join([p.repr(), g0, g1, n, k, iparams['Cx0']])
    return params, (x_sign, x_encr), (y_sign, y_encr), (iparams, i_sk)  # , crs


def req_enroll_1(params, id):
    """
    Generates the secret key l and returns the encrypted l along with a zkp of
    l and r (r is used in elgamal-encryption).
    Returns the tuple (id, l, g0^l, ElGamal-SK, ElGamal-PK, ElGamal-ciphertext, ZKP)
    """
    (G, p, g0, g1) = params
    priv_id = p.random()  # a.k.a. l
    pub_id = priv_id * g0
    return id, priv_id, pub_id, prepare_blind_obtain_cmz(params, priv_id)


def iss_enroll_1(params, iparams, i_sk, gamma, ciphertext, pi_prepare_obtain, id, pub_id, x_sign):
    """
    Returns the elgamal-encrypted credential T(ID) that only the user can
    decrypt and use, as well as a signature on the pub_id
    """
    (G, _, _, _) = params
    pub_id_x, _ = pub_id.get_affine()
    sigma_pub_id = sign(params, x_sign, pub_id_x)
    return sigma_pub_id, blind_issue_cmz(params, iparams, i_sk, gamma, ciphertext, pi_prepare_obtain)


def req_enroll_2(params, iparams, u_sk, u, e_u_prime, pi_issue, biparams, gamma, ciphertext):
    """
    Returns the T(ID), if all goes well.
    """
    return blind_obtain_cmz(params, iparams, u_sk, u, e_u_prime, pi_issue, biparams,
                            gamma, ciphertext)


def enroll(params, id, iparams, i_sk, x_sign):
    """
    Complete Enrollment procedure
    """
    id, priv_id, pub_id, (u_sk, u_pk, c, pi_prepare_obtain) = req_enroll_1(params, id)
    gamma = u_pk['h']
    sigma_pub_id, (u, e_u_prime, pi_issue, biparams) = iss_enroll_1(params, iparams, i_sk, gamma, c, pi_prepare_obtain, id, pub_id, x_sign)
    t_id = req_enroll_2(params, iparams, u_sk, u, e_u_prime, pi_issue, biparams, gamma, c)
    return t_id, sigma_pub_id, pub_id
