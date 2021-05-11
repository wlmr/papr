import logging
from papr_money.bank import Bank
from papr_money.customer_with_issuer import Customer
from papr.ecdsa import verify
import time
#from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Pool, Process


def bootstrap_procedure(k, n, bank):
    params, (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list = bank.setup(k, n)
    (G, p, g0, _) = params
    bootstrap_users = []
    pub_creds_encr = []
    customers = []
    pub_ids = []
    pub_creds = []
    pub_cred_times = []
    # generate credential for each user
    for i in range(n+1):
        customer = Customer(f"customer{i}", bank, 0)
        t_id, sigma_pub_id, pub_id = customer.req_enroll()
        assert verify(G, p, g0, *sigma_pub_id, y_sign, [(customer.name, pub_id)])
        pub_cred = customer.cred_sign_1()
        bootstrap_users.append({"user": customer, "t_id": t_id, "pub_id": pub_id, "pub_cred": pub_cred})
        pub_creds_encr.append(pub_cred[0])
        customer.has_cred = True

        # For external tests
        customers.append(customer)
        pub_ids.append(pub_id)
        pub_creds.append(pub_cred)

    # distribute pub_id for each user
    for bootstrap_user in bootstrap_users:
        t_cred_iss_start = time.perf_counter()
        customer = bootstrap_user['user']
        t_id = bootstrap_user['t_id']
        pub_id = bootstrap_user['pub_id']
        pub_cred = bootstrap_user['pub_cred']

        requester_commit = customer.data_dist_1()
        issuer_random = bank.data_dist_1(pub_cred)
        requester_random, E_list, C_list, proof, group_generator = customer.data_dist_2(issuer_random, pub_creds_encr)
        custodian_list = bank.data_dist_2(requester_commit, requester_random, pub_creds_encr, E_list, C_list, proof, group_generator, pub_cred)

        assert custodian_list is not None
        assert pub_cred[0] not in custodian_list  # Verify that we are not a custodian of ourself

        # Anonymous auth:
        sigma, pi_show, z = customer.anon_auth(t_id)
        assert bank.anon_auth(sigma, pi_show)
        (u2, cl, _) = sigma

        # Proof of eq id:
        y, c, gamma = customer.eq_id(u2, group_generator, z, cl, C_list[0])
        assert bank.eq_id(u2, group_generator, y, c, gamma, cl, C_list[0])
        # Fixme: message to user so that it knows that it can submit credentials (anonymously)

        # Cred signing:
        sigma_pub_cred = bank.cred_sign(pub_cred)
        assert customer.cred_sign_2(sigma_pub_cred)
        (sigma_y_e, sigma_y_s) = sigma_pub_cred
        assert verify(G, p, g0, *sigma_y_e, y_sign, [pub_cred[0]])
        assert verify(G, p, g0, *sigma_y_s, y_sign, [pub_cred[1]])
        pub_cred_times.append(time.perf_counter() - t_cred_iss_start)
    logging.info(f";{k};{n};{sum(pub_cred_times)/len(pub_cred_times)}")
    return customers


# def run_thread(start_nr):

#     step_size_n = 10
#     step_size_k = 5
#     for n in range(270, 1000, step_size_n):
#         for k in range(5 + step_size_k*start_nr, int((n/2)), step_size_k*16):
#             bank = Bank()
#             bootstrap_procedure(k, n, bank)

def run_process(params):
    k, n = params
    bank = Bank()
    bootstrap_procedure(k, n, bank)


if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s %(message)s', filename='load-sim.log', level=logging.INFO)
    logging.info("finish_time;k;n;avg_time")
    params = []
    
    for n in range(200, 300, 10): # TODO: swap range back to 10, 250, 10
        for k in range(5, n, 5):
            params.append((k, n))

    with Pool() as p:
        p.map(run_process, params)
