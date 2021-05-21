from pvss.pvss import participant_decrypt_and_prove
from papr.user import User
import papr.utils as utils


class UserWithIssuer(User):
    def __init__(self, real_id, issuer, x_sign=None):
        self.real_id = real_id
        self.issuer = issuer
        self.params = self.issuer.params
        self.iparams = self.issuer.iparams
        self.y_sign = self.issuer.y_sign
        self.y_encr = self.issuer.y_encr
        self.k, self.n = self.issuer.k, self.issuer.n
        self.is_enrolled = False
        self.has_cred = False
        self.last_rev_list_index_read = 0
        self.last_hash = 0
        super().__init__(self.params, self.iparams, self.y_sign, self.y_encr, self.k, self.n, x_sign)

    def req_enroll(self):
        real_id, pub_id, (u_sk, u_pk, c, pi) = self.req_enroll_1(self.real_id)
        ret = self.issuer.iss_enroll(u_pk['h'], c, pi, real_id, pub_id)
        if ret is not None:
            sigma_pub_id, u, e_u_prime, pi_issue, biparams = ret
            self.t_id = self.req_enroll_2(u_sk, u, e_u_prime, pi_issue, biparams, u_pk['h'], c)
            self.is_enrolled = True
            return self.t_id, sigma_pub_id, pub_id
        print(f"{self.real_id} is already enrolled.")
        return None

    def req_cred(self):
        if self.has_cred:
            print(f"{self.real_id} already has cred")
            return None
        pub_cred = self.cred_sign_1()
        self.issuer.iss_cred(pub_cred)
        sigma, pi, z = self.anon_auth(self.t_id)
        if not self.issuer.anon_auth(sigma, pi):
            return None
        user_commit = self.data_dist_1()
        issuer_rnd = self.issuer.data_dist_1(pub_cred)
        pub_creds_encr = [y_e for (y_e, y_s) in self.issuer.cred_list.read()]
        user_rnd, escrow_shares, commits, pi, group_generator = self.data_dist_2(issuer_rnd, pub_creds_encr)
        custodians = self.issuer.data_dist_2(user_commit, user_rnd, pub_creds_encr, escrow_shares, commits, pi, group_generator, pub_cred)
        if custodians is None:
            return None
        (u, cl, _) = sigma
        y, c, gamma = self.eq_id(u, group_generator, z, cl, commits[0])
        if not self.issuer.eq_id(u, group_generator, y, c, gamma, cl, commits[0]):
            return None
        sigma_pub_cred = self.issuer.cred_sign(pub_cred)
        if not self.cred_sign_2(sigma_pub_cred):
            return None
        self.has_cred = True
        return True

    def show_cred(self):
        m = self.issuer.ver_cred_1()
        sigma_m, pub_cred, sigma_pub_cred = self.show_cred_1(m)
        return self.issuer.ver_cred_2(pub_cred, sigma_pub_cred, m, sigma_m)

    def respond(self, s_e):
        (x_encr, _) = self.priv_cred
        return participant_decrypt_and_prove(self.params, x_encr, s_e)

    def curl_rev_list(self):
        for (pub_cred, (escrow_shares, encryption_keys)) in self.issuer.rev_list.read():
            for i in range(len(encryption_keys)):
                if self.pub_cred[0] == encryption_keys[i]:
                    s_e = escrow_shares[i]
                    self.issuer.get_response(pub_cred, self.pub_cred[0], self.respond(s_e))
        
        #(new_revocations, new_hashes) = self.issuer.rev_list.read_since(self.last_rev_list_index_read)
        #self.last_rev_list_index_read += len(new_revocations)
        #for ((pub_cred, (escrow_shares, encryption_keys)), new_hash) in zip(new_revocations, new_hashes):
        #    if self.check_hash(self.last_hash, new_hash, (pub_cred, (escrow_shares, encryption_keys))):
        #        self.last_hash = new_hash
        #    else:
        #        print("Hash check failed")
        #        return None
        #    for i in range(len(encryption_keys)):
        #        if self.pub_cred[0] == encryption_keys[i]:
        #            s_e = escrow_shares[i]
        #            self.issuer.get_response(pub_cred, self.pub_cred[0], self.respond(s_e))

    def check_hash(self, last_hash, new_hash, entry):
        m = utils.hash([entry, last_hash])
        return new_hash == m
