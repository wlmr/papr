from pvss.pvss import participant_decrypt_and_prove
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
        (_, p, _, g1) = self.params
        self.id = id
        self.priv_id = p.random()  # a.k.a. l
        self.pub_id = self.priv_id * g1
        self.user_sk, self.user_pk, self.ciphertext, self.pi_prepare_obtain = prepare_blind_obtain_cmz(self.params, self.priv_id)
        self.gamma = self.user_pk['h']
        result = self.issuer.iss_enroll(self.gamma, self.ciphertext, self.pi_prepare_obtain, id, self.pub_id)
        self.sigma_pub_id, u, e_u_prime, pi_issue, biparams = result
        self.t_id = blind_obtain_cmz(self.params, self.iparams, self.user_sk, u, e_u_prime, pi_issue, biparams,
                                     self.gamma, self.ciphertext)
        (self.u, self.u_prime) = self.t_id
        return self.t_id

    def req_cred(self):
        (_, _, _, g1) = self.params
        self.pub_cred = self.cred_sign_1()
        sigma, pi_show, z = self.anon_auth()
        if not self.issuer.anon_auth(sigma, pi_show):
            return False
        commit = self.data_dist_1()
        cred_signing_keys_list = [y_s for (y_s, _) in self.issuer.cred_list.read(False)]
        iss_random_value = self.issuer.data_dist_1(self.pub_cred)
        requester_random, escrow_shares, commits, proof, group_generator = self.data_dist_2(iss_random_value, cred_signing_keys_list)
        custodian_list = self.issuer.data_dist_2(commit, requester_random, cred_signing_keys_list,
                                                          escrow_shares, commits, proof, group_generator, self.pub_cred)
        if custodian_list is None:
            return False
        cl = self.priv_id * sigma[0] + z * g1
        c0 = commits[0]
        y, c, gamma = self.eq_id(sigma[0], group_generator, z, cl, c0)
        if not self.issuer.eq_id(sigma[0], group_generator, y, c, gamma, cl, c0):
            return False
        self.sigma_pub_cred = self.issuer.iss_cred_sign(self.pub_cred)
        return True

    def show_cred(self):
        m = self.issuer.ver_cred_1()
        signature = self.show_cred_1(m)
        return self.issuer.ver_cred_2(*signature, self.pub_cred, m)

    # anonymous authentication
    def anon_auth(self):
        """
        sigma = (u, Cm, Cu_prime)
        z is a random value used later in proof of equal identity
        """
        self.sigma, self.pi_show, self.z = blind_show_cmz(self.params, self.iparams, self.t_id, self.priv_id)
        return self.sigma, self.pi_show, self.z

    # Data distrubution
    def data_dist_1(self):
        (commit, self.requester_random) = __data_distrubution_random_commit(self.params)
        return commit

    def data_dist_2(self, issuer_random, pub_keys):
        (_, p, _, _) = self.params
        selected_pub_keys = __data_distrubution_select(pub_keys, self.requester_random, issuer_random, self.n, p)
        E_list, C_list, proof, group_generator = __data_distrubution_commit_encrypt_prove(self.params, self.priv_id, selected_pub_keys, self.k, self.n)
        return self.requester_random, E_list, C_list, proof, group_generator

    # Proof of equal identity
    def eq_id(self, u, h, z, cl, c0):
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
    def cred_sign_1(self):
        (_, p, _, g1) = self.params
        self.priv_cred = (p.random(), p.random())
        pub_cred = (self.priv_cred[0] * g1, self.priv_cred[1] * g1)
        return pub_cred

    def cred_sign_2(self, sigma_pub_cred):
        self.sigma_y_e, self.sigma_y_s = sigma_pub_cred

    # Show/verify credential
    def show_cred_1(self, m):  # Need this from issuer.
        (_, x_sign) = self.priv_cred
        (_, p, _, g1) = self.params
        return sign(p, g1, x_sign, [m])

    # Revoke/restore
    def respond(self, s_e, pub_cred):
        '''
        Responds with decrypted share upon request from L_rev list
        '''
        S_i, decryption_proof = participant_decrypt_and_prove(self.params, self.priv_cred[0], s_e)
        self.issuer.res_list[pub_cred].append((S_i, decryption_proof))




def __data_distrubution_select(public_credentials, u_random, i_random, n, p):
    selected_data_custodians = []
    for i in range(n):
        selected_data_custodians.append(public_credentials[prng(u_random, i_random, i, p) % len(public_credentials)])
    return selected_data_custodians

def __data_distrubution_commit_encrypt_prove(params, PrivID, data_custodians_public_credentials, k, n):
    (Gq, p, _, _) = params
    E_list, C_list, proof, group_generator = pvss.distribute_secret(data_custodians_public_credentials, PrivID, p, k, n, Gq)
    # Send to I
    return E_list, C_list, proof, group_generator



def __data_distrubution_random_commit(params):
    (_, p, _, G) = params
    r = p.random()
    c = r * G  # Is it ok to use G here?
    return (c, r)
