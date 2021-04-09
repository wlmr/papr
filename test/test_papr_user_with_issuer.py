from papr.legacy.papr_user_with_issuer import User
from papr.issuer import Issuer
from papr.ecdsa import sign, verify
import pvss.pvss as pvss
# from petlib.pack import encode, decode
from amac.credential_scheme import setup as setup_cmz


#class TestPaprUserWithIssuer:
#
#     def test_enroll(self):
#         issuer = Issuer()
#         issuer.setup(3, 5)
#         identities = ["Patrik Kron", "Wilmer Nilsson", "Clark Kent", "Ted Kaczynski", "Bruce Wayne"]
#         users = [User(issuer) for _ in identities]
#         t_id_list = [u.req_enroll(id) for id, u in zip(identities, users)]
#         assert t_id_list is not None
#         for u in users:
#             assert u.req_cred()
#    
#     def test_bootstrap(self):
#         (k, n) = (3, 10)
#         issuer = Issuer()
#         (y_sign, y_encr), iparams, _, user_list, _, _ = issuer.setup(k, n)
#    
#         bootstrap_users = []
#         pub_creds_full = []
#         pub_creds = []
#         priv_rev_tuple = []
#         pub_ids = []
#         for i in range(n):
#             user = User(issuer)
#             t_id, s_pub_id, pub_id = self.helper_enroll(str(i), user_list, issuer, user)
#             bootstrap_users.append((user, t_id, s_pub_id, pub_id))
#             PubCred = user.req_cred_sign_1()
#             pub_creds_full.append(PubCred)
#             pub_creds.append(PubCred[0])
#             pub_ids.append(pub_id)
#    
#         for ((user, t_id, s_pub_id, pub_id), pub_cred) in zip(bootstrap_users, pub_creds_full):
#    
#             requester_commit = user.data_dist_1()
#             issuer_random = issuer.data_dist_1(pub_cred)
#             requester_random, E_list, C_list, proof, group_generator = user.data_dist_2(issuer_random, pub_creds)
#             custodian_list = issuer.data_dist_2(requester_commit, requester_random, pub_creds, E_list, C_list, proof, group_generator, pub_cred)
#    
#             (_, p, _, _) = params
#    
#             assert custodian_list is not None
#    
#             # Anonimous auth:
#             sigma, pi_show, z = user.anon_auth(t_id)
#             assert issuer.anon_auth(sigma, pi_show)
#             (u2, cl, _) = sigma
#    
#             # Proof of eq id:
#             y, c, gamma = user.eq_id(u2, group_generator, z, cl, C_list[0])
#             assert issuer.eq_id(u2, group_generator, y, c, gamma, cl, C_list[0])
#             # Fixme: message to user so that it knows that it can submit credentails (anonimously)
#    
#             priv_rev_tuple.append((pub_cred, E_list, custodian_list))
#    
#         (pub_cred, E_list, cust_pub_keys) = priv_rev_tuple[0]
#    
#         decoded_list = []
#    
#         indexes = []
#    
#         for (enc_share, cust_pub_key) in zip(E_list, cust_pub_keys):
#             # Here cusodian sees there key and answers. In this test instead we look up the private key.
#             for (i, pub_k) in zip(range(len(pub_creds)), pub_creds):
#                 if pub_k == cust_pub_key:
#                     # Here we skip reading from list, since we only test restore
#                     user = (bootstrap_users[i])[0]
#                     decoded_list.append(user.respond(enc_share))
#                     indexes.append(i+1)
#    
#         answer = issuer.restore(decoded_list[:3], [1, 2, 3], cust_pub_keys[:3], E_list[:3])
#         assert answer is not None
#         assert answer == pub_ids[0]
#    
#         # Test another order and other numbers for decryption.
#         answer = issuer.restore([decoded_list[0], decoded_list[3], decoded_list[1]], [1, 4, 2], [
#                                 cust_pub_keys[0], cust_pub_keys[3], cust_pub_keys[1]], [E_list[0], E_list[3], E_list[1]])
#         assert answer is not None
#         assert answer == pub_ids[0]
#    
#         # [x] Enc shares empty. : Fixed
#         # [ ] Index repeat sometimes?
#         # [ ] verify correct decryption fail, called in issuer.restore