from amac.credential_scheme import prepare_blind_obtain as prepare_blind_obtain_cmz
from amac.credential_scheme import blind_obtain as blind_obtain_cmz
from amac.credential_scheme import blind_show as blind_show_cmz
from amac.proofs import to_challenge
from papr.ecdsa import sign
from pvss.pvss import distribute_secret
from papr.utils import prng

from petlib.pack import encode, decode
import grpc

from papr.papr_pb2 import iss_enroll_msg, iss_enroll_rsp
from papr.papr_pb2_grpc import ConnectorStub
from papr.issuer import Issuer


class User():

    def __init__(self, params, iparams, y_sign, y_encr, k, n):
        self.params = params
        self.iparams = iparams
        self.y_sign = y_sign
        self.y_encr = y_encr
        self.k, self.n = (k, n)
        self.conn = Connector()

    def req_enroll(self, id):
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
        self.gamma = self.user_pk['h']
        msg = make_iss_enroll_msg(id, self.pub_id, self.gamma, self.ciphertext, self.pi_prepare_obtain)
        rsp = self.conn.stub.iss_enroll(msg)
        self.sigma_pub_id, u, e_u_prime, pi_issue, biparams = unpack_iss_enroll_rsp(rsp)
        self.u, self.u_prime = blind_obtain_cmz(self.params, self.iparams, self.user_sk, u, e_u_prime, pi_issue, biparams,
                                                self.gamma, self.ciphertext)
    # anonymous authentication

    def anon_auth(self, t_id):
        """
        sigma = (u, Cm, Cu_prime)
        z is a random value used later in proof of equal identity
        """
        self.sigma, self.pi_show, self.z = blind_show_cmz(self.params, self.iparams, t_id, self.priv_id)
        return self.sigma, self.pi_show, self.z

    # Data distrubution
    def data_dist_1(self):
        (commit, self.requester_random) = data_distrubution_random_commit(self.params)
        return commit

    def data_dist_2(self, issuer_random, pub_keys):
        (_, p, _, _) = self.params
        selected_pub_keys = data_distrubution_select(pub_keys, self.requester_random, issuer_random, self.n, p)
        return self.requester_random, self.params, self.priv_id, selected_pub_keys, self.k, self.n

    # Proof of equal identity
    def eq_id(self, u, h, z, cl, c0):
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
    def cred_sign(self):
        (_, p, _, g1) = self.params
        PrivCred = (p.random(), p.random())
        PubCred = (PrivCred[0] * g1, PrivCred[1] * g1)
        return PrivCred, PubCred

    # Show/verify credential
    def show_cred_1(self, privCred, sigma_i_pub_cred, m):
        (_, p, g0, _) = self.params
        (_, x_sign) = privCred
        return sign(p, g0, x_sign, [m])

    # Revoke/restore
    def respond(self, L_res, params, s_e, priv_key):
        '''
        Responds with decrypted share upon request from L_rev list
        '''
        pass
        # return
        # L_res.add(params, participant_decrypt_and_prove(params, priv_key))
        # Publish s_r_i to L_res


class Connector():

    def __init__(self) -> None:
        channel = grpc.insecure_channel('localhost:50051')
        self.stub = ConnectorStub(channel)


def make_iss_enroll_msg(id, pub_id, gamma, ciphertext, proof):
    return iss_enroll_msg(load=encode([id, pub_id, gamma, ciphertext, proof]))


def unpack_iss_enroll_rsp(rsp):
    [sigma_pub_id, u, e_u_prime, pi_issue, biparams] = decode(rsp.load)
    # print("sigma_pub_id: ", sigma_pub_id, "u ", u, "e_u_prime: ", e_u_prime, "pi_issue: ", pi_issue, "biparams: ", biparams)
    return tuple(sigma_pub_id), u, e_u_prime, tuple(pi_issue), biparams


if __name__ == '__main__':
    issuer = Issuer()
    id = "Abradolf Lincler"
    (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list = issuer.setup(3, 10)
    user = User(issuer.get_params(), iparams, y_sign, y_encr, 3, 10)
    user.req_enroll(id)


def data_distrubution_select(public_credentials, u_random, i_random, n, p):
    selected_data_custodians = []
    for i in range(n):
        selected_data_custodians.append(public_credentials[prng(u_random, i_random, i, p) % len(public_credentials)])
    return selected_data_custodians


def data_distrubution_commit_encrypt_prove(params, PrivID, data_custodians_public_credentials, k, n):
    (Gq, p, _, _) = params
    E_list, C_list, proof, group_generator = distribute_secret(data_custodians_public_credentials, PrivID, p, k, n, Gq)
    # Send to I
    return E_list, C_list, proof, group_generator


def data_distrubution_random_commit(params):
    (_, p, _, G) = params
    r = p.random()
    c = r * G  # Is it ok to use G here?
    return (c, r)
