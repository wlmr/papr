from papr.ecdsa import verify
from papr_money.customer_with_issuer import Customer


def bootstrap_procedure(k, n, bank, login_interval):
    params, (y_sign, _), _, _, _, _, _ = bank.setup(k, n)
    (G, p, g0, _) = params
    bootstrap_users = []
    pub_creds_encr = []
    customers = []
    pub_ids = []
    pub_creds = []
    # generate credential for each user
    for i in range(n+1):
        customer = Customer(f"customer{i}", bank, login_interval[i])
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

        # Cred signing:
        sigma_pub_cred = bank.cred_sign(pub_cred)
        assert customer.cred_sign_2(sigma_pub_cred)
        (sigma_y_e, sigma_y_s) = sigma_pub_cred
        assert verify(G, p, g0, *sigma_y_e, y_sign, [pub_cred[0]])
        assert verify(G, p, g0, *sigma_y_s, y_sign, [pub_cred[1]])
    return customers
