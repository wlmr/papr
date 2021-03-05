from amac.credential_scheme import setup, cred_keygen, prepare_blind_obtain
from amac.credential_scheme import blind_issue, blind_obtain, blind_show, show_verify


class TestAmac():
    
    def test_valid_procedure(self):
        params = setup(1)
        (G, p, g, h) = params
        (iparams, i_sk) = cred_keygen(params)
        m = p.from_binary(b"DreadPirateRoberts")
        (u_sk, u_pk, ciphertext, pi_prepare_obtain) = prepare_blind_obtain(params, m)
        (u, e_u_prime, pi_issue, biparams) = blind_issue(params, iparams, i_sk, u_pk['h'], ciphertext, pi_prepare_obtain)
        cred = blind_obtain(params, iparams, u_sk, u, e_u_prime, pi_issue, biparams, u_pk['h'], ciphertext)
        (sigma, pi_show) = blind_show(params, iparams, cred, m)
        assert show_verify(params, iparams, i_sk, sigma, pi_show)

    def test_altered_pi_prepare_obtain(self):
        params = setup(1)
        (G, p, g, h) = params
        (iparams, i_sk) = cred_keygen(params)
        m = p.from_binary(b"DreadPirateRoberts")
        (u_sk, u_pk, ciphertext, (_, response)) = prepare_blind_obtain(params, m)
        c = p.from_decimal("100")
        pi_prepare_obtain = (c, response)
        assert blind_issue(params, iparams, i_sk, u_pk['h'], ciphertext, pi_prepare_obtain) == None

