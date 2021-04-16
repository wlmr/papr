from papr.user import User
from papr.issuer import Issuer
from papr.ecdsa import sign, verify
import pvss.pvss as pvss
from amac.credential_scheme import setup as setup_cmz
import pytest
import time




def helper_enroll(id, issuer, user):
    """
    Complete Enrollment procedure. Inputs:
    id: real identity, i_sk: issuer's secret key for CMZ,
    x_sign: issuer's secret signature key, user_list: the list of users (ID: pub_ID) as described in PAPR.
    """
    id, pub_id, (u_sk, u_pk, c, pi_prepare_obtain) = user.req_enroll_1(id)
    ret = issuer.iss_enroll(u_pk['h'], c, pi_prepare_obtain, id, pub_id)
    if ret is not None:
        s_pub_id, u, e_u_prime, pi_issue, biparams = ret
        t_id = user.req_enroll_2(u_sk, u, e_u_prime, pi_issue, biparams, u_pk['h'], c)
        return t_id, s_pub_id, pub_id
    print("user already exists")
    return None

def bootstrap_procedure(k, n, issuer):
        params, (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list = issuer.setup(k, n)
        (G, p, g0, _) = params
        bootstrap_users = []
        pub_creds_encr = []

        users = []
        pub_ids = []
        pub_creds = []

        # generate pub_creds for each user
        for i in range(n+1):
            user = User(params, iparams, y_sign, y_encr, k, n)
            t_id, sigma_pub_id, pub_id = helper_enroll(str(i), issuer, user)
            assert verify(G, p, g0, *sigma_pub_id, y_sign, [(str(i), pub_id)])
            pub_cred = user.cred_sign_1()
            bootstrap_users.append({"user": user, "t_id": t_id, "pub_id": pub_id, "pub_cred": pub_cred})
            pub_creds_encr.append(pub_cred[0])

            # For external tests
            users.append(user)
            pub_ids.append(pub_id)
            pub_creds.append(pub_cred)

        # distribute pub_id for each user
        for dict_elem in bootstrap_users:
            user = dict_elem['user']
            t_id = dict_elem['t_id']
            pub_id = dict_elem['pub_id']
            pub_cred = dict_elem['pub_cred']

            requester_commit = user.data_dist_1()
            issuer_random = issuer.data_dist_1(pub_cred)
            requester_random, E_list, C_list, proof, group_generator = user.data_dist_2(issuer_random, pub_creds_encr)
            custodian_list = issuer.data_dist_2(requester_commit, requester_random, pub_creds_encr, E_list, C_list, proof, group_generator, pub_cred)

            assert custodian_list is not None
            assert pub_cred[0] not in custodian_list  # Verify that we are not a custodian of ourself

            # Anonymous auth:
            sigma, pi_show, z = user.anon_auth(t_id)
            assert issuer.anon_auth(sigma, pi_show)
            (u2, cl, _) = sigma

            # Proof of eq id:
            y, c, gamma = user.eq_id(u2, group_generator, z, cl, C_list[0])
            assert issuer.eq_id(u2, group_generator, y, c, gamma, cl, C_list[0])
            # Fixme: message to user so that it knows that it can submit credentails (anonymously)

            # Cred signing:
            sigma_pub_cred = issuer.cred_sign(pub_cred)
            assert user.cred_sign_2(sigma_pub_cred)
            (sigma_y_e, sigma_y_s) = sigma_pub_cred
            assert verify(G, p, g0, *sigma_y_e, y_sign, [pub_cred[0]])
            assert verify(G, p, g0, *sigma_y_s, y_sign, [pub_cred[1]])

        return issuer, sys_list, user_list, cred_list, rev_list, users, pub_creds, pub_ids








k_max = 51 #51
n_max = 100 #100
for k in range(3,k_max):
    for n in range(k,n_max):
        issuer = Issuer()

        begin = time.time()
    
        # Bootstrap 
        issuer, sys_list, user_list, cred_list, rev_list, users, pub_creds, pub_ids = bootstrap_procedure(k, n, issuer)
        end = time.time()

        print("(" + str(k) +  ", " + str(n) + "): " + str(end-begin) + " s")

