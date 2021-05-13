from papr_money.customer_with_issuer import Customer
from papr_money.bank import Bank
from random import choice, gauss
import logging
from concurrent.futures import ThreadPoolExecutor
import time
from simulation.procedures import bootstrap_procedure
from queue import PriorityQueue
from dataclasses import dataclass, field
from typing import Any


nbr_of_customers = 20
seconds_per_day = 10
mu = 2 * seconds_per_day
sigma = 1 * seconds_per_day
login_interval = [gauss(mu, sigma) for _ in range(nbr_of_customers)]
revocation_timer = {}
d_time_logins = 5 * seconds_per_day  # days
d_time_revokations = 1 * seconds_per_day  # day
rev_counter = 0
bank = Bank()
customers = []
customer_queue = PriorityQueue()
start_time = time.perf_counter()
k, n = 4, 5


@dataclass(order=True)
class PrioritizedCustomer:
    t_next_login: float
    customer: Any = field(compare=False)


def run():
    global customers
    customers = bootstrap_procedure(k, n, bank, login_interval)
    customers = customers + [Customer(f"customer{i}", bank, login_interval[i]) for i in range(n+1, nbr_of_customers)]
    for i in range(nbr_of_customers):
        customer_queue.put(PrioritizedCustomer(time.perf_counter(), customers[i]))
    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.submit(customer_thread_run)
        executor.submit(run_bank_thread)


def customer_thread_run():
    while not customer_queue.empty():
        now = time.perf_counter()
        entry = customer_queue.get()
        delta = entry.t_next_login - now
        if delta > 0:
            print(f"{entry.customer.name} is ahead of time")
            time.sleep(delta)
        else:
            print(f"{entry.customer.name} arrived late")
        entry.customer.nbr_logins += 1
        has_been_revoked = run_customer(entry.customer)
        entry.t_next_login = now + entry.customer.login_interval
        if not has_been_revoked:
            customer_queue.put(entry)
        else:
            logging.info(f"{entry.customer.name} saw their name in rev_list and decided to log off forever")
    logging.info("All customers have stopped answering since they are revoked")


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
            return True
        else:
            customer.curl_rev_list()
            address = choice(list(customer.issuer.registry.values()))
            # txnid = customer.send(address, 1, "satoshi")
            logging.info(f"{customer.name} sent 1 satoshi to {address}")
    return False


def run_bank_thread():
    rev_request_counter = 0
    rev_complete_counter = 0
    revoked = set()
    revoking = set()
    time.sleep(d_time_logins)
    global revocation_timer
    no_more_left_to_revoke = False
    while not no_more_left_to_revoke:
        rev_pub_cred = choice(bank.cred_list.read())
        while rev_pub_cred in revoking:
            if len(revoking) >= nbr_of_customers:
                no_more_left_to_revoke = True
                break
            rev_pub_cred = choice(bank.cred_list.read())
        revocation_timer[rev_pub_cred] = [time.perf_counter()]
        logging.info("The Bank is revoking a public credential!")
        rev_request_counter += 1
        revoking.add(rev_pub_cred)
        bank.get_rev_data(rev_pub_cred)
        # restore part
        for rev_pub_cred, _ in bank.rev_list.read():
            if rev_pub_cred not in revoked:
                rev_pub_id = bank.restore(rev_pub_cred)
                if rev_pub_id is not None:
                    rev_complete_counter += 1
                    revocation_timer[rev_pub_cred].append(time.perf_counter())
                    revoked.add(rev_pub_cred)
                    for identity, pub_id in bank.user_list.read():
                        if rev_pub_id == pub_id:
                            logging.info(
                                f"""Bank revoked {identity}. {rev_complete_counter} out of {rev_request_counter} requests has been successfully revoked.""")
        time.sleep(d_time_revokations)

    # Run restore an extra time for all users to have a chance to answer:
    time.sleep(max(login_interval))
    for rev_pub_cred, _ in bank.rev_list.read():
        if rev_pub_cred not in revoked:
            rev_pub_id = bank.restore(rev_pub_cred)
            if rev_pub_id is not None:
                rev_complete_counter += 1
                revocation_timer[rev_pub_cred].append(time.perf_counter())
                revoked.add(rev_pub_cred)
                for identity, pub_id in bank.user_list.read():
                    if rev_pub_id == pub_id:
                        logging.info(
                            f"""Bank revoked {identity}. {rev_complete_counter} out of {rev_request_counter} requests has been successfully revoked.""")
    logging.info(
        f"""Restore have run one extra time after all users have been revoked. Stopping. {rev_complete_counter} out of {rev_request_counter} requests has been successfully revoked.""")


def print_revocation_times():
    """
    Prints the delta revocation time, for each request.
    """
    with open(f"{k}-{n}-{nbr_of_customers}-revocation-times.log", "w") as file:
        file.write("BEGIN\n")
        [file.write(f"{t[0]}: revocation request nbr {i+1}! Restored after {t[1]-t[0]} seconds, ({(t[1]-t[0])/seconds_per_day} days)\n")
         if len(t) == 2
         else file.write(f"{t[0]}: revocation request nbr {i+1}! Was never restored. Time since request: {time.perf_counter()-t[0]} seconds, ({(time.perf_counter()-t[0])/seconds_per_day} days)\n")
         for (k, t), i in zip(revocation_timer.items(), range(len(revocation_timer)))]
        file.write("END\n")


def print_nbr_logins():
    """
    Just to check that the queue is working, and that no one gets left out.
    """
    with open(f"{k}-{n}-{nbr_of_customers}-nbr-of-logins_per_user.log", "w") as file:
        file.write("BEGIN\n")
        [file.write(f"{c.name}: {c.nbr_logins}, (login interval: {c.login_interval/seconds_per_day} day(s))\n")
         for c in customers]
        file.write("END\n")


def main():
    logging.basicConfig(format='%(asctime)s %(message)s', filename=f'revocation_delay_{k}_{n}_sim.log', level=logging.INFO)
    logging.info('Started')
    run()
    logging.info('Finished')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    finally:
        print_revocation_times()
        print_nbr_logins()
