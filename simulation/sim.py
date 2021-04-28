from papr_money.customer_with_issuer import Customer
from papr_money.bank import Bank
from papr.utils import pub_key_to_addr
import random
import logging
from concurrent.futures import ThreadPoolExecutor
import time
from simulation.procedures import bootstrap_procedure
from queue import PriorityQueue
from dataclasses import dataclass, field
from typing import Any


d_time_logins = 60
d_time_revokations = 15
rev_counter = 0
bank = Bank()
customers = []
customer_queue = PriorityQueue()
nbr_of_customers = 10000
start_time = time.perf_counter()


@dataclass(order=True)
class PrioritizedCustomer:
    priority: float
    customer: Any = field(compare=False)


def run():
    k, n = 3, 10
    customers = bootstrap_procedure(k, n, bank)
    customers = customers + [Customer("customer" + str(i), bank) for i in range(n+1, nbr_of_customers)]
    for c in customers:
        customer_queue.put(PrioritizedCustomer(time.perf_counter(), c))
    with ThreadPoolExecutor(max_workers=2) as executor:
        [executor.submit(customer_thread_run) for _ in range(executor._max_workers-1)]
        executor.submit(run_bank_thread)


def customer_thread_run():
    while True:
        now = time.perf_counter()
        entry = customer_queue.get()
        delta = now - entry.priority
        # print(f"{entry.customer.name} was added {entry.priority}, delta: {delta}")
        if delta > d_time_logins:
            run_customer(entry.customer)
            entry.priority = now
            customer_queue.put(entry)
        else:
            time.sleep(d_time_logins - delta)
            run_customer(entry.customer)
            entry.priority = now
            customer_queue.put(entry)


def run_customer(customer):
    if not customer.is_enrolled:
        if customer.req_enroll() is not None:
            customer.is_enrolled = True
            logging.info(f"{customer.name} was enrolled.")
    elif not customer.has_cred:
        if customer.req_cred():
            customer.has_cred = True
            logging.info(f"{customer.name} was issued credentials.")
    elif customer.show_cred():
        if customer.pub_cred in [pub_cred for pub_cred, _ in bank.rev_list.read()]:
            return
        else:
            customer.curl_rev_list()
            address = random.choice(list(customer.issuer.registry.values()))
            # txnid = customer.send(address, 1, "satoshi")
            logging.info(f"{customer.name} sent 1 satoshi to {address}")


def run_bank_thread():
    rev_counter = 0
    revoked = set()
    # should poll the rev_list more or less constantly and try to restore the entries
    # should only get_rev_data every d_time_revokation
    while True:
        pub_cred = random.choice(bank.cred_list.read())
        while pub_cred in revoked:
            pub_cred = random.choice(bank.cred_list.read())
        rev_counter += 1
        logging.info("bank is revoking a public credential!")
        bank.get_rev_data(pub_cred)
        # restore part
        for pub_cred, _ in bank.rev_list.read():
            if pub_cred not in revoked:
                pub_id = bank.restore(pub_cred)
                if pub_id is not None:
                    revoked.add(pub_cred)
                    for identity, pub_id_tmp in bank.user_list.read():
                        if pub_id == pub_id_tmp:
                            logging.info(f"bank has revoked {identity}.")
        time.sleep(d_time_revokations)


def main():
    logging.basicConfig(format='%(asctime)s %(message)s', filename='sim.log', level=logging.INFO)
    logging.info('Started')
    run()
    logging.info('Finished')


if __name__ == '__main__':
    main()
