from papr.issuer import Issuer
from concurrent import futures
import grpc
from petlib.pack import decode, encode
from papr_pb2 import get_public_params_rsp, iss_enroll_rsp
from papr_pb2_grpc import ConnectorServicer, add_ConnectorServicer_to_server


class Grpc_server(ConnectorServicer):
    def __init__(self, issuer):
        self.issuer = issuer

    def get_public_params(self, request, context):
        return make_get_public_params_rsp(self.issuer.setup())

    def iss_enroll(self, request, context):
        id, pub_id, gamma, ciphertext, proof = unpack_iss_enroll_msg(request)
        sigma_pub_id, u, e_u_prime, pi_issue, biparams = self.issuer.iss_enroll(id, pub_id, gamma, ciphertext, proof)
        return make_iss_enroll_rsp(sigma_pub_id, u, e_u_prime, pi_issue, biparams)

    def anon_auth(self, request, context):
        pass

    def data_dist_1(self, request, context):
        pass

    def data_dist_2(self, request, context):
        pass

    def eq_id(self, request, context):
        pass

    def cred_sign(self, request, context):
        pass

    def ver_cred_1(self, request, context):
        pass

    def ver_cred_2(self, request, context):
        pass


def unpack_get_public_params_msg(msg):
    pass


def unpack_iss_enroll_msg(msg):
    [id, pub_id, gamma, ciphertext, proof] = decode(msg.load)
    return id, pub_id, gamma, ciphertext, proof


def unpack_ver_cred_2_msg(msg):
    pass


def unpack_ver_cred_1_msg(msg):
    pass


def unpack_cred_sign_msg(msg):
    pass


def unpack_eq_id_msg(msg):
    pass


def unpack_data_dist_2_msg(msg):
    pass


def unpack_data_dist_1_msg(msg):
    pass


def unpack_anon_auth_msg(msg):
    pass


def make_get_public_params_rsp(y_sign, y_encr, iparams, sys_list, user_list, cred_list, rev_list, res_list):
    return get_public_params_rsp(load=encode([y_sign, y_encr, iparams]))


def make_iss_enroll_rsp(sigma_pub_id, u, e_u_prime, pi_issue, biparams):
    # print("sigma_pub_id: ", sigma_pub_id, "u ", u, "e_u_prime: ", e_u_prime, "pi_issue: ", pi_issue, "biparams: ", biparams)
    return iss_enroll_rsp(load=encode([sigma_pub_id, u, e_u_prime, pi_issue, biparams]))


def make_ver_cred_2_rsp():
    pass


def make_ver_cred_1_rsp():
    pass


def make_cred_sign_rsp():
    pass


def make_eq_id_rsp():
    pass


def make_data_dist_2_rsp():
    pass


def make_data_dist_1_rsp():
    pass


def make_anon_auth_rsp():
    pass


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    add_ConnectorServicer_to_server(Grpc_server(Issuer()), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()


if __name__ == '__main__':
    serve()
