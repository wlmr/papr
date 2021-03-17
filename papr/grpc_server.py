from papr.papr_issuer import Issuer
from concurrent import futures
import grpc
from petlib.pack import decode, encode
from papr_pb2 import iss_enroll_rsp
from papr_pb2_grpc import ConnectorServicer, add_ConnectorServicer_to_server


class Grpc_server(ConnectorServicer):
    def __init__(self, issuer):
        self.issuer = issuer

    def get_public_params(self, request, context):
        pass

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


def unpack_iss_enroll_msg(msg):
    [id, pub_id, gamma, ciphertext, proof] = decode(msg.load)
    return id, pub_id, gamma, ciphertext, proof


def make_iss_enroll_rsp(sigma_pub_id, u, e_u_prime, pi_issue, biparams):
    # print("sigma_pub_id: ", sigma_pub_id, "u ", u, "e_u_prime: ", e_u_prime, "pi_issue: ", pi_issue, "biparams: ", biparams)
    return iss_enroll_rsp(load=encode([sigma_pub_id, u, e_u_prime, pi_issue, biparams]))


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    add_ConnectorServicer_to_server(Grpc_server(Issuer()), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()


if __name__ == '__main__':
    serve()
