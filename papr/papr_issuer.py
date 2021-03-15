from pvss.pvss import reconstruct, verify_correct_decryption
from papr.papr_cred_iss_data_dist import data_distrubution_issuer_verify, data_distrubution_random_commit, \
    data_distrubution_select, data_distrubution_verify_commit
from amac.credential_scheme import setup as setup_cmz, cred_keygen as cred_keygen_cmz
from amac.credential_scheme import blind_issue as blind_issue_cmz
from amac.credential_scheme import show_verify as show_verify_cmz
from amac.proofs import to_challenge
from papr.ecdsa import sign, verify
from papr.papr_list import Papr_list


class Issuer():
    def __init__(self):
        self.params = Null

    def get_params(self):
        return self.params

    def setup(self, k, n):
        """
        k, n defines the PVSS-threshold scheme
        Generates the CRS, and all the system values that it consists of.

        TODO: [ ] publish return value to Lsys.
        """
        self.params = setup_cmz(1)
        (_, p, g0, g1) = self.params
        (x_sign, x_encr) = (p.random(), p.random())
        (y_sign, y_encr) = (x_sign * g0, x_encr * g0)
        (iparams, i_sk) = cred_keygen_cmz(self.params)
        crs = ",".join([str(elem) for elem in [p.repr(), g0, g1, n, k, iparams['Cx0']]])
        i_pk = ",".join([str(x) for x in [y_sign, y_encr]])
        [sys_list, user_list, cred_list, rev_list, res_list] = [Papr_list(y_sign) for _ in range(5)]

        sys_list.add(self.params, crs, sign(self.params, x_sign, [crs]))
        sys_list.add(self.params, i_pk, sign(self.params, x_sign, [i_pk]))
        return (x_sign, x_encr), (y_sign, y_encr), (iparams, i_sk), sys_list, user_list, cred_list, rev_list, res_list

    def iss_enroll(self, iparams, i_sk, gamma, ciphertext, pi_prepare_obtain, id, pub_id, x_sign, user_list):
        """
        Returns the elgamal-encrypted credential T(ID) that only the user can
        decrypt and use, as well as a signature on the pub_id
        """
        if not user_list.has(id, 0):
            sigma_pub_id = sign(self.params, x_sign, [id, pub_id])
            if user_list.add(params, (id, pub_id), sigma_pub_id):
                return sigma_pub_id, blind_issue_cmz(self.params, iparams, i_sk, gamma, ciphertext, pi_prepare_obtain), user_list
        return None

    # anonymous authentication
    def iss_cred_anon_auth(self, iparams, i_sk, sigma, pi_show):
        return show_verify_cmz(self.params, iparams, i_sk, sigma, pi_show)

    # Data distrubution
    def iss_cred_data_dist_1(self):
        return data_distrubution_random_commit(self.params)

    def iss_cred_data_dist_2(self, requester_commit, requester_random, issuer_random, pub_keys, n):
        (_, p, _, _) = self.params
        if data_distrubution_verify_commit(self.params, requester_commit, requester_random):
            return data_distrubution_select(pub_keys, requester_random, issuer_random, n, p)
        else:
            return None

    def iss_cred_data_dist_3(self, E_list, C_list, proof, custodian_list, group_generator):
        (_, p, _, _) = self.params
        return data_distrubution_issuer_verify(E_list, C_list, proof, custodian_list, group_generator, p)

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
    def iss_cred_sign(self, iss_priv_key, new_pub_cred):
        sigma_y_e = sign(self.params, iss_priv_key, new_pub_cred[0])
        sigma_y_s = sign(self.params, iss_priv_key, new_pub_cred[1])
        # FIXME: AND Publish PubCred
        return (sigma_y_e, sigma_y_s)

    # Show/verify credential
    def ver_cred_1(self, r, s, pub_cred, m):
        (y_encr, y_sign) = pub_cred
        return verify(self.params, r, s, y_sign, [m])

    # Revoke/restore
    def get_rev_data(self, PubCred, dummy_list):
        '''
        Publishes to L_rev the request to revoce the privacy corresponging to PubCred
        '''
        pass
        # FIXME: Publish to L_rev

    def restore(self, proved_decrypted_shares, index_list, custodian_public_keys, encrypted_shares):
        '''
        Restores public key given a set of at least k shares that's decrypted and proven, along with encrypted shares,
            custodian public keys and a list of which indexes are used for decryption
        '''
        (_, p, _, G) = self.params
        S_r = []
        for ((S_i, decrypt_proof), Y_i, pub_key) in zip(proved_decrypted_shares, encrypted_shares, custodian_public_keys):
            S_r.append(S_i)
            if not verify_correct_decryption(S_i, Y_i, decrypt_proof, pub_key, p, G):
                return None
        return reconstruct(S_r, index_list, p)
        # Return pub_id
