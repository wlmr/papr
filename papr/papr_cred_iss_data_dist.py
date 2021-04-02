import pvss.pvss_wrapper as pvss
from papr.utils import hash


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


def data_distrubution_commit_encrypt_prove(params, PrivID, data_custodians_public_credentials, k, n):
    (Gq, p, _, _) = params
    E_list, C_list, proof, group_generator = pvss.distribute_secret(data_custodians_public_credentials, PrivID, p, k, n, Gq)
    # Send to I
    return E_list, C_list, proof, group_generator


def data_distrubution_issuer_verify(E_list, C_list, proof, pub_keys, group_generator, p):
    result = pvss.verify_encrypted_shares(E_list, C_list, pub_keys, proof, group_generator, p)
    if result:
        # Contrinue to "Proof of equal identity"
        return True
    else:
        # Discard
        return False


def prng(random_u, random_i, counter, p):
    return int(hash([random_u, random_i, counter]) % p)
