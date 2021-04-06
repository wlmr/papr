from pvss.pvss import reconstruct, verify_correct_decryption
from papr.papr_cred_iss_data_dist import data_distrubution_issuer_verify, \
    data_distrubution_select, data_distrubution_verify_commit
from amac.credential_scheme import setup as setup_cmz, cred_keygen as cred_keygen_cmz
from amac.credential_scheme import blind_issue as blind_issue_cmz
from amac.credential_scheme import show_verify as show_verify_cmz
from amac.proofs import to_challenge
from papr.ecdsa import sign, verify
from papr.papr_list import Papr_list


class Issuer():
    def __init__(self):
        self.rev_data = {}
        self.temp_creds = {}
        self.res_list = {}

    def get_params(self):
        return self.params

    def setup(self, k, n):
        """
        k, n defines the PVSS-threshold scheme
        Generates the CRS, and all the system values that it consists of.

        TODO: [ ] publish return value to Lsys.
        """
        self.k = k
        self.n = n
        self.params = setup_cmz(1)
        (_, p, g0, g1) = self.params
        (self.x_sign, self.x_encr) = (p.random(), p.random())
        (self.y_sign, self.y_encr) = (self.x_sign * g0, self.x_encr * g0)
        (self.iparams, self.i_sk) = cred_keygen_cmz(self.params)
        crs = ",".join([str(elem) for elem in [p.repr(), g0, g1, n, k, self.iparams['Cx0']]])
        i_pk = ",".join([str(x) for x in [self.y_sign, self.y_encr]])
        [self.sys_list, self.user_list, self.cred_list, self.rev_list] = [Papr_list(self.y_sign) for _ in range(4)]
        self.sys_list.add(self.params, crs, sign(p, g0, self.x_sign, [crs]))
        self.sys_list.add(self.params, i_pk, sign(p, g0, self.x_sign, [i_pk]))  # Note: Should we publish i_pk, or should it be y_sign, y_encr
        return (self.y_sign, self.y_encr), self.iparams, self.sys_list, self.user_list, self.cred_list, self.rev_list  # , self.res_list

    def iss_enroll(self, gamma, ciphertext, pi_prepare_obtain, id, pub_id):
        """
        Returns the elgamal-encrypted credential T(ID) that only the user can
        decrypt and use, as well as a signature on the pub_id
        """
        if not self.user_list.has(id, 0):
            (_, p, g0, _) = self.params
            sigma_pub_id = sign(p, g0, self.x_sign, [id, pub_id])
            if self.user_list.add(self.params, (id, pub_id), sigma_pub_id):
                u, e_u_prime, pi_issue, biparams = blind_issue_cmz(self.params, self.iparams,
                                                                   self.i_sk, gamma, ciphertext, pi_prepare_obtain)
                return sigma_pub_id, u, e_u_prime, pi_issue, biparams
        return None

    def iss_cred(self, pub_cred):
        self.temp_creds[pub_cred] = []

    # anonymous authentication
    def iss_cred_anon_auth(self, sigma, pi_show):
        return show_verify_cmz(self.params, self.iparams, self.i_sk, sigma, pi_show)

    # Data distrubution
    def iss_cred_data_dist_1(self, pub_cred):
        (_, p, _, _) = self.params
        issuer_random = p.random()
        self.temp_creds[pub_cred] = {'issuer_random': issuer_random}
        return issuer_random

    def iss_cred_data_dist_2(self, requester_commit, requester_random, pub_keys, escrow_shares, commits, proof, group_generator, pub_cred):
        (_, p, _, _) = self.params
        if data_distrubution_verify_commit(self.params, requester_commit, requester_random):
            custodians = data_distrubution_select(pub_keys, requester_random, self.temp_creds[pub_cred]['issuer_random'], self.n, p)
            if data_distrubution_issuer_verify(escrow_shares, commits, proof, custodians, group_generator, p):
                self.temp_creds[pub_cred]['custodians'] = custodians
                self.temp_creds[pub_cred]['escrow_shares'] = escrow_shares
                return custodians
            else:
                return None
        else:
            return None

    # Proof of equal identity
    def iss_cred_eq_id(self, u, h, y, c, gamma, cl, c0):
        """
        Third step of ReqCred, i.e. proof of equal identity.
        From Chaum et al.'s: "An Improved Protocol for Demonstrating Possession
        of Discrete Logarithms and Some Generalizations".
        Protocol 3 Relaxed Discrete Log.
        (With the added benefit of letting the challenge, c, be a hash of public values,
        rendering the method non-interactive).
        """
        (G, _, _, g1) = self.params
        a = [u + h, g1]
        lhs = sum([y * a for y, a in zip(y, a)], G.infinite())
        rhs = sum(gamma, G.infinite()) + (c * (cl + c0))
        return c == to_challenge(a + gamma + [cl + c0]) and lhs == rhs

    # Credential signing
    def iss_cred_sign(self, pub_cred):
        (_, p, g0, _) = self.params
        escrow_shares = self.temp_creds[pub_cred]['escrow_shares']
        custodian_encr_keys = self.temp_creds[pub_cred]['custodians']
        del self.temp_creds[pub_cred]
        self.rev_data[pub_cred] = (escrow_shares, custodian_encr_keys)
        sigma_y_e = sign(p, g0, self.x_sign, pub_cred[0])
        sigma_y_s = sign(p, g0, self.x_sign, pub_cred[1])
        self.cred_list.add(self.params, pub_cred, sign(p, g0, self.x_sign, pub_cred))
        self.res_list[pub_cred] = []
        return (sigma_y_e, sigma_y_s)

    # Show/verify credential
    def ver_cred_1(self):
        (_, p, _, _) = self.params
        return p.random()  # m

    def ver_cred_2(self, r, s, pub_cred, m):
        (_, y_sign) = pub_cred
        (G, p, g0, _) = self.params
        return verify(G, p, g0, r, s, y_sign, [m])

    # Revoke/restore
    def get_rev_data(self, pub_cred):
        '''
        Publishes to L_rev the request to revoce the privacy corresponging to PubCred
        '''
        (_, p, g0, _) = self.params
        self.rev_list.add(self.params, (pub_cred, self.rev_data[pub_cred]), sign(p, g0, self.x_sign, (pub_cred, self.rev_data[pub_cred])))

    def restore(self, proved_decrypted_shares, index_list, custodian_public_keys, encrypted_shares):
        '''
        Restores public key given a set of at least k shares that's decrypted and proven, along with encrypted shares,
            custodian public keys and a list of which indexes are used for decryption
        '''
        (_, p, g0, _) = self.params
        S_r = []
        for ((S_i, decrypt_proof), Y_i, pub_key) in zip(proved_decrypted_shares, encrypted_shares, custodian_public_keys):
            S_r.append(S_i)
            if not verify_correct_decryption(S_i, Y_i, decrypt_proof, pub_key, p, g0):
                return None
        return reconstruct(S_r, index_list, p)
        # Return pub_id
