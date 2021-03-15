from papr.papr_cred_iss_data_dist import data_distrubution_commit_encrypt_prove, data_distrubution_random_commit, \
    data_distrubution_select, data_distrubution_verify_commit
from amac.credential_scheme import prepare_blind_obtain as prepare_blind_obtain_cmz
from amac.credential_scheme import blind_obtain as blind_obtain_cmz
from amac.credential_scheme import blind_show as blind_show_cmz
from amac.proofs import to_challenge
from papr.ecdsa import sign

class User(): 

    def set_params(self, params):
        self.params = params

    def req_enroll_1(self, id):
        """
        Generates the secret key l and returns the encrypted l along with a zkp of
        l and r (r is used in elgamal-encryption).
        Returns the tuple (id, l, g0^l, ElGamal-SK, ElGamal-PK, ElGamal-ciphertext, ZKP)
        """
        (_, p, g0, _) = self.params
        priv_id = p.random()  # a.k.a. l
        pub_id = priv_id * g0
        return id, priv_id, pub_id, prepare_blind_obtain_cmz(params, priv_id)


    def req_enroll_2(self, iparams, u_sk, u, e_u_prime, pi_issue, biparams, gamma, ciphertext):
        """
        Returns the T(ID), if all goes well.
        """
        return blind_obtain_cmz(self.params, iparams, u_sk, u, e_u_prime, pi_issue, biparams,
                                gamma, ciphertext)


    # anonymous authentication
    def req_cred_anon_auth(self, iparams, t_id, priv_id):
        sigma, pi_show, z = blind_show_cmz(self.params, iparams, t_id, priv_id)
        return sigma, pi_show, z


    # Data distrubution
    def req_cred_data_dist_1(self):
        return data_distrubution_random_commit(self.params)


    def req_cred_data_dist_2(self, issuer_commit, issuer_random):
        return data_distrubution_verify_commit(self.params, issuer_commit, issuer_random)


    def req_cred_data_dist_3(self, requester_random, issuer_random, PrivID, pub_keys, k, n):
        (_, p, _, _) = self.params
        selected_pub_keys = data_distrubution_select(pub_keys, requester_random, issuer_random, n, p)
        return data_distrubution_commit_encrypt_prove(self.params, PrivID, selected_pub_keys, k, n)


    # Proof of equal identity
    def req_cred_eq_id(self, u, h, priv_id, z, cl, c0):
        """
        Third step of ReqCred, i.e. proof of equal identity.
        From Chaum et al.'s: "An Improved Protocol for Demonstrating Possession
        of Discrete Logarithms and Some Generalizations".
        Protocol 3 Relaxed Discrete Log.
        (With the added benefit of letting the challenge, c, be a hash of public values,
        rendering the method non-interactive).
        """
        (_, p, _, g1) = self.params
        secret = [priv_id, z]
        alpha = [u + h, g1]
        r = [p.random(), p.random()]
        gamma = [r * a for r, a in zip(r, alpha)]
        c = to_challenge(alpha + gamma + [cl + c0])
        y = [(r + c * dl) % p for r, dl in zip(r, secret)]
        return y, c, gamma


    # Credential signing
    def req_cred_sign(self):
        (_, p, _, g1) = self.params
        PrivCred = (p.random(), p.random())
        PubCred = (PrivCred[0] * g1, PrivCred[1] * g1)
        return PrivCred, PubCred


    # Show/verify credential
    def show_cred_1(self, privCred, sigma_i_pub_cred, m):
        (x_encr, x_sign) = privCred
        return sign(self.params, x_sign, [m])


    # Revoke/restore
    def respond(self, L_res, params, s_e, priv_key):
        '''
        Responds with decrypted share upon request from L_rev list
        '''
        pass
        # return
        # L_res.add(params, participant_decrypt_and_prove(params, priv_key))
        # Publish s_r_i to L_res
