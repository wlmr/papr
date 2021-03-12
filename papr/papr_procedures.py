from pvss.pvss import reconstruct, verify_correct_decryption
from papr.papr_cred_iss_data_dist import data_distrubution_issuer_verify, data_distrubution_commit_encrypt_prove, data_distrubution_random_commit, \
     data_distrubution_select, data_distrubution_verify_commit
from amac.credential_scheme import setup as setup_cmz, cred_keygen as cred_keygen_cmz
from amac.credential_scheme import prepare_blind_obtain as prepare_blind_obtain_cmz
from amac.credential_scheme import blind_issue as blind_issue_cmz
from amac.credential_scheme import blind_obtain as blind_obtain_cmz
from amac.credential_scheme import blind_show as blind_show_cmz
from amac.credential_scheme import show_verify as show_verify_cmz
from amac.proofs import to_challenge
from papr.ecdsa import sign, verify
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
    sigma, pi_show, z = blind_show_cmz(params, iparams, t_id, priv_id)
    return sigma, pi_show, z


def iss_cred_anon_auth(params, iparams, i_sk, sigma, pi_show):
    return show_verify_cmz(params, iparams, i_sk, sigma, pi_show)


def req_cred_data_dist_1(params):
    return data_distrubution_random_commit(params)


def iss_cred_data_dist_1(params):
    return data_distrubution_random_commit(params)


def req_cred_eq_id(params, u, h, priv_id, z, cl, c0):
    """
    Third step of ReqCred, i.e. proof of equal identity.
    From Chaum et al.'s: "An Improved Protocol for Demonstrating Possession
    of Discrete Logarithms and Some Generalizations".
    Protocol 3 Relaxed Discrete Log.
    (With the added benefit of letting the challenge, c, be a hash of public values,
    rendering the method non-interactive).
    """
    (_, p, _, g1) = params
    secret = [priv_id, z]
    alpha = [u + h, g1]
    r = [p.random(), p.random()]
    gamma = [r * a for r, a in zip(r, alpha)]
    c = to_challenge(alpha + gamma + [cl + c0])
    y = [(r + c * dl) % p for r, dl in zip(r, secret)]
    return y, c, gamma


def iss_cred_eq_id(params, u, h, y, c, gamma, cl, c0):
    """
    Third step of ReqCred, i.e. proof of equal identity.
    From Chaum et al.'s: "An Improved Protocol for Demonstrating Possession
    of Discrete Logarithms and Some Generalizations".
    Protocol 3 Relaxed Discrete Log.
    (With the added benefit of letting the challenge, c, be a hash of public values,
    rendering the method non-interactive).
    """
    (G, _, _, g1) = params
    a = [u + h, g1]
    lhs = sum([y * a for y, a in zip(y, a)], G.infinite())
    rhs = sum(gamma, G.infinite()) + (c * (cl + c0))
    return c == to_challenge(a + gamma + [cl + c0]) and lhs == rhs


# ----
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
    return data_distrubution_commit_encrypt_prove(params, PrivID, selected_pub_keys, k, n)


def iss_cred_data_dist_3(params, E_list, C_list, proof, custodian_list, group_generator):
    (_, p, _, _) = params
    return data_distrubution_issuer_verify(E_list, C_list, proof, custodian_list, group_generator, p)


def show_cred_1(params, privCred, sigma_i_pub_cred, m):
    (x_encr, x_sign) = privCred
    return sign(params, x_sign, [m])


def ver_cred_1(params, r, s, pub_cred, m):
    (y_encr, y_sign) = pub_cred
    return verify(params, r, s, y_sign, [m])


def restore(params, proved_decrypted_shares, index_list, custodian_public_keys, encrypted_shares):
    '''
    Restores public key given a set of at least k shares that's decrypted and proven, along with encrypted shares,
        custodian public keys and a list of which indexes are used for decryption
    '''
    (_, p, _, G) = params
    S_r = []
    for ((S_i, decrypt_proof), Y_i, pub_key) in zip(proved_decrypted_shares, encrypted_shares, custodian_public_keys):
        S_r.append(S_i)
        if not verify_correct_decryption(S_i, Y_i, decrypt_proof, pub_key, p, G):
            return None
    return reconstruct(S_r, index_list, p)
    # Return pub_id


def respond(L_res, params, s_e, priv_key):
    '''
    Responds with decrypted share upon request from L_rev list
    '''
    pass
    # return
    # L_res.add(params, participant_decrypt_and_prove(params, priv_key))
    # Publish s_r_i to L_res


def get_rev_data(PubCred, dummy_list):
    '''
    Publishes to L_rev the request to revoce the privacy corresponging to PubCred
    '''
    pass
    # Publish to L_rev
