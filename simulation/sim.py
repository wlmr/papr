from papr_money.customer_with_issuer import Customer
from papr_money.bank import Bank
from papr.ecdsa import verify
import random
import logging
from concurrent.futures import ThreadPoolExecutor
import time

d_time_logins = 10
d_time_revokations = 10


def run():
    k, n = 3, 10
    bank = Bank()
    customers = bootstrap_procedure(k, n, bank)
    customers = customers + [Customer("customer" + str(i), bank) for i in range(n+1, 100)]
    with ThreadPoolExecutor() as executor:
        executor.map(run_customer, customers)


def run_customer(customer):
    if not customer.is_enrolled:
        if customer.req_enroll() is not None:
            customer.is_enrolled = True
            logging.info(f"{customer.name} was enrolled.")
    elif not customer.has_cred:
        if customer.req_cred():
            customer.has_cred = True
            logging.info(f"{customer.name} was issued credentials.")
    else:
        if customer.show_cred():
            customer.curl_rev_list()
            address = random.choice(list(customer.issuer.registry.values()))
            # txnid = customer.send(address, 1, "satoshi")
            logging.info(f"{customer.name} sent 1 satoshi to {address} belonging to {customer.issuer.registry[address][1]}")  # txnid: {txnid}")
    time.sleep(d_time_logins)


def bootstrap_procedure(k, n, bank):
    params, (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list = bank.setup(k, n)
    (G, p, g0, _) = params
    bootstrap_users = []
    pub_creds_encr = []
    customers = []
    pub_ids = []
    pub_creds = []
    # generate pub_creds for each user
    for i in range(n+1):
        customer = Customer("customer"+str(i), bank)
        t_id, sigma_pub_id, pub_id = customer.req_enroll()
        assert verify(G, p, g0, *sigma_pub_id, y_sign, [(customer.name, pub_id)])
        pub_cred = customer.cred_sign_1()
        bootstrap_users.append({"user": customer, "t_id": t_id, "pub_id": pub_id, "pub_cred": pub_cred})
        pub_creds_encr.append(pub_cred[0])

        # For external tests
        customers.append(customer)
        pub_ids.append(pub_id)
        pub_creds.append(pub_cred)

    # distribute pub_id for each user
    for bootstrap_user in bootstrap_users:
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
        # Fixme: message to user so that it knows that it can submit credentails (anonymously)

        # Cred signing:
        sigma_pub_cred = bank.cred_sign(pub_cred)
        assert customer.cred_sign_2(sigma_pub_cred)
        (sigma_y_e, sigma_y_s) = sigma_pub_cred
        assert verify(G, p, g0, *sigma_y_e, y_sign, [pub_cred[0]])
        assert verify(G, p, g0, *sigma_y_s, y_sign, [pub_cred[1]])
    return customers
    # return params, (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list, users, pub_creds, pub_ids


def main():
    logging.basicConfig(filename='sim.log', level=logging.INFO)
    logging.info('Started')
    run()
    logging.info('Finished')


if __name__ == '__main__':
    main()
