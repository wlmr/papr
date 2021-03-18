from pvss.pvss import participant_decrypt_and_prove
from papr.papr_cred_iss_data_dist import data_distrubution_commit_encrypt_prove, data_distrubution_random_commit, \
    data_distrubution_select
from amac.credential_scheme import prepare_blind_obtain as prepare_blind_obtain_cmz
from amac.credential_scheme import blind_obtain as blind_obtain_cmz
from amac.credential_scheme import blind_show as blind_show_cmz
from amac.proofs import to_challenge
from papr.ecdsa import sign


class User():

    def __init__(self, issuer):
        self.issuer = issuer
        self.params = self.issuer.params
        self.iparams = self.issuer.iparams
        self.y_sign = self.issuer.y_sign
        self.y_encr = self.issuer.y_encr
        self.k, self.n = self.issuer.k, self.issuer.n

    def req_enroll(self, id):
        """
        Generates the secret key l and returns the encrypted l along with a zkp of
        l and r (r is used in elgamal-encryption).
        Returns the tuple (id, l, g0^l, ElGamal-SK, ElGamal-PK, ElGamal-ciphertext, ZKP)
        Returns the T(ID), if all goes well.
        """
        (_, p, g0, _) = self.params
        self.id = id
        self.priv_id = p.random()  # a.k.a. l
        self.pub_id = self.priv_id * g0
        self.gamma = self.user_pk['h']
        self.user_sk, self.user_pk, self.ciphertext, self.pi_prepare_obtain = prepare_blind_obtain_cmz(self.params, self.priv_id)
        result = self.issuer.iss_enroll(self.gamma, self.ciphertext, self.pi_prepare_obtain, id, self.pub_id)
        self.sigma_pub_id, u, e_u_prime, pi_issue, biparams = result
        self.t_id = blind_obtain_cmz(self.params, self.iparams, self.user_sk, u, e_u_prime, pi_issue, biparams,
                                     self.gamma, self.ciphertext)
        (self.u, self.u_prime) = self.t_id
        return self.t_id

    def req_cred(self):
        (_, _, _, g1) = self.params
        pub_cred = self.req_cred_sign_1()
        sigma, pi_show, z = self.req_cred_anon_auth(self.t_id)
        if not self.issuer.iss_cred_anon_auth(sigma, pi_show):
            return None
        commit = self.req_cred_data_dist_1()
        cred_signing_keys_list = [y_s for (y_s, _) in self.issuer.cred_list.read()]
        iss_random_value = self.issuer.iss_cred_data_dist_1(pub_cred)
        requester_random, escrow_shares, commits, proof, group_generator = self.req_cred_data_dist_2(iss_random_value, cred_signing_keys_list)
        custodian_list = self.issuer.iss_cred_data_dist_2(commit, requester_random, cred_signing_keys_list, escrow_shares, commits, proof, group_generator, pub_cred)
        if custodian_list is None:
            return None
        cl = self.priv_id * sigma[0] + z * g1
        c0 = commits[0]
        y, c, gamma = self.req_cred_eq_id(sigma[0], group_generator, z, cl, c0)
        if not self.issuer.iss_cred_eq_id(sigma[0], group_generator, y, c, gamma, cl, c0):
            return None
        self.issuer.iss_cred_sign(pub_cred)

    # anonymous authentication
    def req_cred_anon_auth(self):
        """
        sigma = (u, Cm, Cu_prime)
        z is a random value used later in proof of equal identity
        """
        self.sigma, self.pi_show, self.z = blind_show_cmz(self.params, self.iparams, self.t_id, self.priv_id)
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
        u = sigma[0], h is a generator from pvss,
        z is a random value generated in blind_show_cmz, cl = u^l * g1^z and
        c0 is the first commit in commits.
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
    def req_cred_sign_1(self):
        (_, p, _, g1) = self.params
        self.priv_cred = (p.random(), p.random())
        pub_cred = (self.priv_cred[0] * g1, self.priv_cred[1] * g1)
        return pub_cred

    def req_cred_sign_2(self, sigma_pub_cred):
        self.sigma_y_e, self.sigma_y_s = sigma_pub_cred

    # Show/verify credential
    def show_cred_1(self, m):  # Need this from issuer.
        (_, x_sign) = self.priv_cred
        (G, p, _, g1) = self.params
        return sign(p, g1, x_sign, [m])

    # Revoke/restore
    def respond(self, s_e):
        '''
        Responds with decrypted share upon request from L_rev list
        '''
        return participant_decrypt_and_prove(self.params, self.x_i, s_e)
