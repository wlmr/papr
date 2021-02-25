from amac.credential_scheme import setup, cred_keygen, prepare_blind_obtain
from amac.credential_scheme import blind_issue, blind_obtain, blind_show, show_verify

if __name__ == "__main__":
    params = setup(1)
    (iparams, i_sk) = cred_keygen(params, 1)
    m = b"DreadPirateRoberts"
    (u_sk, u_pk, ciphertext, pi_prepare_obtain) = prepare_blind_obtain(params, m)
    (u, e_u_prime, pi_issue, biparams) = blind_issue(params, iparams, i_sk, u_pk['h'], ciphertext, pi_prepare_obtain)
    cred = blind_obtain(params, iparams, u_sk, u, e_u_prime, pi_issue, biparams, u_pk['h'], ciphertext)
    (sigma, pi_show) = blind_show(params, iparams, cred, m)
    assert show_verify(params, iparams, i_sk, sigma, pi_show)
