
from papr.papr_cred_iss_data_dist import data_distrubution_commit_encrypt_prove, data_distrubution_random_commit, \
    data_distrubution_select, data_distrubution_verify_commit
from amac.credential_scheme import prepare_blind_obtain as prepare_blind_obtain_cmz
from amac.credential_scheme import blind_obtain as blind_obtain_cmz
from amac.credential_scheme import blind_show as blind_show_cmz
from amac.proofs import to_challenge
from papr.ecdsa import sign

from petlib.pack import encode
import grpc

from papr.papr_pb2 import iss_enroll_msg, iss_enroll_rsp
from papr.papr_pb2_grpc import ConnectorStub


class User():

    def __init__(self, params, iparams, y_sign, y_encr, k, n):
        self.params = params
        self.iparams = iparams
        self.y_sign = y_sign
        self.y_encr = y_encr
        self.k, self.n = (k, n)
        self.conn = Connector()

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
        self.conn.stub.iss_enroll(iss_enroll_msg(id=id, pub_id=encode(self.pub_id)))
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


class Connector():

    def __init__(self) -> None:
        channel = grpc.insecure_channel('localhost:50051')
        self.stub = ConnectorStub(channel)
