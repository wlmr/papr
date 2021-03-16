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
        pass

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
        [self.sys_list, self.user_list, self.cred_list, self.rev_list, self.res_list] = [Papr_list(self.y_sign) for _ in range(5)]

        self.sys_list.add(self.params, crs, sign(self.params, self.x_sign, [crs]))
        self.sys_list.add(self.params, i_pk, sign(self.params, self.x_sign, [i_pk]))  # Note: Should we publish i_pk, or should it be y_sign, y_encr
        return (self.y_sign, self.y_encr), self.iparams, self.sys_list, self.user_list, self.cred_list, self.rev_list, self.res_list

    def iss_enroll(self, gamma, ciphertext, pi_prepare_obtain, id, pub_id, user_list):
        """
        Returns the elgamal-encrypted credential T(ID) that only the user can
        decrypt and use, as well as a signature on the pub_id
        """
        if not user_list.has(id, 0):
            sigma_pub_id = sign(self.params, self.x_sign, [id, pub_id])
            if user_list.add(self.params, (id, pub_id), sigma_pub_id):
                return sigma_pub_id, blind_issue_cmz(self.params, self.iparams, self.i_sk, gamma, ciphertext, pi_prepare_obtain)
        return None

    # anonymous authentication
    def iss_cred_anon_auth(self, sigma, pi_show):
        return show_verify_cmz(self.params, self.iparams, self.i_sk, sigma, pi_show)

    # Data distrubution
    def iss_cred_data_dist_1(self):
        (_, p, _, _) = self.params
        self.issuer_random = p.random()
        return self.issuer_random  # FIXME: Make sure it's a new one for every user. And make sure transactin made in parallel (NOT possible now)

    def iss_cred_data_dist_2(self, requester_commit, requester_random, pub_keys, E_list, C_list, proof, group_generator):
        (_, p, _, _) = self.params
        if data_distrubution_verify_commit(self.params, requester_commit, requester_random):
            # NOTE: Should be enouth to save this and return if it succeed or not.
            custodian_list = data_distrubution_select(pub_keys, requester_random, self.issuer_random, self.n, p)
            # FIXME: Save custodian_list in relation to user (alternativly save parameters needed to recreate)
            if data_distrubution_issuer_verify(E_list, C_list, proof, custodian_list, group_generator, p):
                return custodian_list
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
    def iss_cred_sign(self, new_pub_cred):
        sigma_y_e = sign(self.params, self.x_sign, new_pub_cred[0])
        sigma_y_s = sign(self.params, self.x_sign, new_pub_cred[1])
        # FIXME: AND Publish PubCred
        self.cred_list.add(self.params, (sigma_y_e, sigma_y_s), sign(self.params, self.x_sign, (sigma_y_e, sigma_y_s)))
        # Should this be published along with something else?
        return (sigma_y_e, sigma_y_s)

    # Show/verify credential
    def ver_cred_1(self):
        (_, p, _, _) = self.params
        return p.random()  # m

    def ver_cred_2(self, r, s, pub_cred, m):
        (_, y_sign) = pub_cred
        return verify(self.params, r, s, y_sign, [m])

    # Revoke/restore
    def get_rev_data(self, PubCred):
        '''
        Publishes to L_rev the request to revoce the privacy corresponging to PubCred
        '''
        self.rev_list.add(self.params, PubCred, sign(self.params, self.x_sign, PubCred))

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
