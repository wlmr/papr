from pvss.pvss import participant_decrypt_and_prove
from papr.papr_cred_iss_data_dist import data_distrubution_commit_encrypt_prove, data_distrubution_random_commit, \
    data_distrubution_select
from amac.credential_scheme import prepare_blind_obtain as prepare_blind_obtain_cmz
from amac.credential_scheme import blind_obtain as blind_obtain_cmz
from amac.credential_scheme import blind_show as blind_show_cmz
from amac.proofs import to_challenge
from papr.ecdsa import sign


class User():

    def __init__(self, params, iparams, y_sign, y_encr, k, n, private_authentication_key=None):
        self.params = params
        self.iparams = iparams
        self.y_sign = y_sign
        self.y_encr = y_encr
        self.k, self.n = (k, n)
        if private_authentication_key is None:
            (_, p, _, _) = params
            self.private_authentication_key = p.random()
        else:
            self.private_authentication_key = private_authentication_key

    def req_enroll_1(self, id):
        """
        Generates the secret key l and returns the encrypted l along with a zkp of
        l and r (r is used in elgamal-encryption).
        Returns the tuple (id, l, g0^l, ElGamal-SK, ElGamal-PK, ElGamal-ciphertext, ZKP)
        """
        (_, p, g0, _) = self.params
        self.id = id
        self.priv_id = p.random()  # a.k.a. l
        self.pub_id = self.priv_id * g0
        self.user_sk, self.user_pk, self.ciphertext, self.pi_prepare_obtain = prepare_blind_obtain_cmz(self.params, self.priv_id)
        return self.id, self.pub_id, (self.user_sk, self.user_pk, self.ciphertext, self.pi_prepare_obtain)

    def req_enroll_2(self, u_sk, u, e_u_prime, pi_issue, biparams, gamma, ciphertext):
        """
        Returns the T(ID), if all goes well.
        """
        self.u, self.u_prime = blind_obtain_cmz(self.params, self.iparams, u_sk, u, e_u_prime, pi_issue, biparams,
                                                gamma, ciphertext)
        return self.u, self.u_prime

    # anonymous authentication
    def req_cred_anon_auth(self, t_id):
        """
        sigma = (u, Cm, Cu_prime)
        z is a random value used later in proof of equal identity
        """
        self.sigma, self.pi_show, self.z = blind_show_cmz(self.params, self.iparams, t_id, self.priv_id)
        return self.sigma, self.pi_show, self.z

    # Data distrubution
    def req_cred_data_dist_1(self):
        (commit, self.requester_random) = data_distrubution_random_commit(self.params)
        return commit

    def req_cred_data_dist_2(self, issuer_random, pub_keys):
        (_, p, _, _) = self.params
        selected_pub_keys = data_distrubution_select(pub_keys, self.requester_random, issuer_random, self.n, p)
        E_list, C_list, proof, group_generator = data_distrubution_commit_encrypt_prove(self.params, self.priv_id, selected_pub_keys, self.k, self.n)
        return self.requester_random, E_list, C_list, proof, group_generator

    # Proof of equal identity
    def req_cred_eq_id(self, u, h, z, cl, c0):
        """
        Third step of ReqCred, i.e. proof of equal identity.
        From Chaum et al.'s: "An Improved Protocol for Demonstrating Possession
        of Discrete Logarithms and Some Generalizations".
        Protocol 3 Relaxed Discrete Log.
        (With the added benefit of letting the challenge, c, be a hash of public values,
        rendering the method non-interactive).
        """
        (_, p, _, g1) = self.params
        secret = [self.priv_id, z]
        alpha = [u + h, g1]
        r = [p.random(), p.random()]
        gamma = [r * a for r, a in zip(r, alpha)]
        c = to_challenge(alpha + gamma + [cl + c0])
        y = [(r + c * dl) % p for r, dl in zip(r, secret)]
        return y, c, gamma

    # Credential signing
    def req_cred_sign(self):
        (_, p, g0, g1) = self.params
        self.priv_cred = (p.random(),  self.private_authentication_key)
        pub_cred = (self.priv_cred[0] * g0, self.priv_cred[1] * g0)
        return pub_cred

    # Show/verify credential
    def show_cred_1(self, m):  # Need this from issuer.
        (_, x_sign) = self.priv_cred
        (G, p, g0, g1) = self.params
        return sign(p, g0, x_sign, [m])

    # Revoke/restore
    def respond(self, s_e):
        '''
        Responds with decrypted share upon request from L_rev list
        '''
        (x_encr, x_sign) = self.priv_cred
        return participant_decrypt_and_prove(self.params, x_encr, s_e)
