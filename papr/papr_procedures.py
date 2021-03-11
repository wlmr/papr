from amac.credential_scheme import setup as setup_cmz, cred_keygen as cred_keygen_cmz
from amac.credential_scheme import prepare_blind_obtain as prepare_blind_obtain_cmz
from amac.credential_scheme import blind_issue as blind_issue_cmz
from amac.credential_scheme import blind_obtain as blind_obtain_cmz
from amac.credential_scheme import blind_show as blind_show_cmz
from amac.credential_scheme import show_verify as show_verify_cmz
from papr.ecdsa import sign
from papr.papr_list import Papr_list
import pvss.pvss as pvss
from papr.utils import hash


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
    [sys_list, user_list, cred_list, rev_list, res_list] = [Papr_list(y_sign) for _ in range(5)]

    sys_list.add(params, crs, sign(params, x_sign, [crs]))
    sys_list.add(params, i_pk, sign(params, x_sign, [i_pk]))
    return params, (x_sign, x_encr), (y_sign, y_encr), (iparams, i_sk), sys_list, user_list, cred_list, rev_list, res_list


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


def cred(params, iparams, t_id, priv_id, i_sk):
    sigma, pi_show = req_cred_anon_auth(params, iparams, t_id, priv_id)
    iss_cred_anon_auth(params, iparams, i_sk, sigma, pi_show)


# anonymous authentication

def req_cred_anon_auth(params, iparams, t_id, priv_id):
    sigma, pi_show = blind_show_cmz(params, iparams, t_id, priv_id)
    return sigma, pi_show


def iss_cred_anon_auth(params, iparams, i_sk, sigma, pi_show):
    return show_verify_cmz(params, iparams, i_sk, sigma, pi_show)


def req_cred_data_dist_1(params):
    return data_distrubution_random_commit(params)


def iss_cred_data_dist_1(params):
    return data_distrubution_random_commit(params)


def req_cred_data_dist_2(params, issuer_commit, issuer_random):
    return data_distrubution_verify_commit(params, issuer_commit, issuer_random)


def iss_cred_data_dist_2(params, requester_commit, requester_random, issuer_random, pub_keys, n):
    (_, p, _, _) = params
    if data_distrubution_verify_commit(params, requester_commit, requester_random):
        return data_distrubution_select(pub_keys, requester_random, issuer_random, n, p)
    else:
        return None


def req_cred_data_dist_3(params, requester_random, issuer_random, PrivID, pub_keys, k, n):
    (_, p, _, _) = params
    selected_pub_keys = data_distrubution_select(pub_keys, requester_random, issuer_random, n, p)
    return data_distrubution_U_2(params, PrivID, selected_pub_keys, k, n)


def iss_cred_data_dist_3(params, E_list, C_list, proof, custodian_list, group_generator):
    (_, p, _, _) = params
    return data_distrubution_I_2(E_list, C_list, proof, custodian_list, group_generator, p)

# r1 U generates a random number and commitment req_cred_data_dist_1 and sends the commitment to I.
# i1 I stores the commitment, generates a random value with commitment and sends commitment to U. 
# r2 U sends the commited to random value to I, 
# i2 I responds with their random value. **??** And calculates which custodians to use and stores it.
# r3 U recives the random value and calulates the custodians, and generates a encrypted shares to the custodians, commitments and proof 
# i3 I verifies proof. If valid. Proof of identity is initaited.  


# ----

# def data_distrubution_U_1(params):
#     (_, p, _, _) = params
#     return p.random()


# def data_distrubution_I_1(params):
#     (_, p, _, _) = params
#     return p.random()


def data_distrubution_random_commit(params):
    (_, p, _, G) = params
    r = p.random()
    c = r * G  # Is it ok to use G here?
    return (c, r)


def data_distrubution_verify_commit(params, c, r):
    (_, p, _, G) = params
    commit = r * G  # Is it ok to use G here?
    return commit == c


def data_distrubution_select(public_credentials, u_random, i_random, n, p):
    selected_data_custodians = []
    for i in range(n):
        selected_data_custodians.append(public_credentials[prng(u_random, i_random, i, p) % len(public_credentials)])
    return selected_data_custodians


def data_distrubution_U_2(params, PrivID, data_custodians_public_credentials, k, n):
    (Gq, p, _, _) = params
    E_list, C_list, proof, group_generator = pvss.distribute_secret(data_custodians_public_credentials, PrivID, p, k, n, Gq)
    # Send to I
    return E_list, C_list, proof, group_generator


def data_distrubution_I_2(E_list, C_list, proof, pub_keys, group_generator, p):
    result = pvss.verify_encrypted_shares(E_list, C_list, pub_keys, proof, group_generator, p)
    if result:
        # Contrinue to "Proof of equal identity"
        return True
    else:
        # Discard
        return False


def prng(random_u, random_i, counter, p):
    return int(hash([random_u, random_i, counter]) % p)
