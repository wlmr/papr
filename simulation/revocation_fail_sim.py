from papr_money.customer_with_issuer import Customer
from papr_money.bank import Bank
from random import choice
import logging
from simulation.procedures import bootstrap_procedure
from queue import Queue
from multiprocessing import Pool


def run(params):
    # setup
    k, n, nbr_of_customers = params
    logging.basicConfig(format='%(message)s', filename=f'revocation_fail.log', level=logging.INFO)
    customers = []
    rev_counter = 0
    rev_fail_counter = 0
    rev_requests = 0
    bank = Bank()
    login_interval = [0] * nbr_of_customers
    revoked = set()
    revoking = set()
    customers = bootstrap_procedure(k, n, bank, login_interval)
    customers = customers + [Customer(f"customer{i}", bank, 0) for i in range(n+1, nbr_of_customers)]
    for c in customers:
        if not c.is_enrolled:
            c.req_enroll()
        if not c.has_cred:
            c.req_cred()
    # main loop
    while rev_counter + rev_fail_counter < nbr_of_customers:
        # revocation request issued
        rev_pub_cred = choice(bank.cred_list.read())
        while rev_pub_cred in revoking:
            rev_pub_cred = choice(bank.cred_list.read())
        revoking.add(rev_pub_cred)
        bank.get_rev_data(rev_pub_cred)
        rev_requests += 1
        # all users have a chance to answer
        for c in customers:
            if c.pub_cred not in [pub_cred for pub_cred, _ in bank.rev_list.read()]:
                c.curl_rev_list()
        # issuer checks if it was successful
        rev_pub_id = bank.restore(rev_pub_cred)
        if rev_pub_id is not None:
            rev_counter += 1
            revoked.add(rev_pub_cred)
        else:
            rev_fail_counter += 1
        logging.info(f"\"{k}, {n}\";{rev_counter+rev_fail_counter};{rev_counter};{rev_fail_counter}")


if __name__ == '__main__':
    run((50,100,1000))
    # params = [(10, 100, 1000), (3, 10, 1000), (30, 100, 1000), (5, 10, 1000), (50, 100, 1000), (9, 10, 1000), (90, 100, 1000)]
    # with Pool() as p:
    #     p.map(run, params)
