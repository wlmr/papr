from papr_money.vendor import Vendor
from papr_money.customer import Customer
from papr.ecdsa import verify
import pytest


class TestPaprMoney:

    def test_vendor_persistence(self):
        vendor = Vendor()
        vendor.registry['address1'] = 'pubkey1'
        vendor.registry['address2'] = 'pubkey2'
        vendor.registry['address3'] = 'pubkey3'
        pubkey1 = vendor.key.public_key
        del vendor
        vendor = Vendor()
        assert pubkey1 == vendor.key.public_key
        assert vendor.registry['address1'] == 'pubkey1'

    @pytest.mark.skip(reason="Disable since github actions creates a new wallet every run. Therefore the wallet will always be empty.")
    # NOTE: give Tito more coins if this test fails
    def test_customer_balance(self):
        k, n = 3, 10
        vendor = Vendor()
        params, (y_sign, y_encr), iparams, _, _, _, _ = vendor.setup(3, 10)
        customer = Customer("Josip Tito", vendor, params, iparams, y_sign, y_encr, k, n)
        assert float(customer.get_balance("satoshi")) > 0.0

    def test_customer_persistence(self):
        k, n = 3, 10
        vendor = Vendor()
        params, (y_sign, y_encr), iparams, _, _, _, _ = vendor.setup(3, 10)
        customer = Customer("Josip Tito", vendor, params, iparams, y_sign, y_encr, k, n)
        addr1 = customer.get_address()
        customer2 = Customer("Josip Tito", vendor, params, iparams, y_sign, y_encr, k, n)
        addr2 = customer2.get_address()
        assert addr1 == addr2

    def test_new_user_procedure(self):
        k, n = 3, 5
        vendor = Vendor()
        sys_list, user_list, cred_list, rev_list, customers, pub_creds, pub_ids = self.bootstrap_procedure(k, n, vendor)
        self.authentication_procedure(customers[0], vendor)
        pub_id_revealed = self.revoke_procedure(vendor, rev_list, customers, pub_creds[0]) 

        for id, pub_id in user_list.read():
            if pub_id_revealed == pub_id:
                print(id)
                assert id == "0"

    def enroll_procedure(self, id, vendor, customer):
        """
        Complete Enrollment procedure. Inputs:
        id: real identity, i_sk: issuer's secret key for CMZ,
        x_sign: issuer's secret signature key, user_list: the list of users (ID: pub_ID) as described in PAPR.
        """
        id, pub_id, (u_sk, u_pk, c, pi_prepare_obtain) = customer.req_enroll_1(id)
        ret = vendor.iss_enroll(u_pk['h'], c, pi_prepare_obtain, id, pub_id)
        if ret is not None:
            s_pub_id, u, e_u_prime, pi_issue, biparams = ret
            t_id = customer.req_enroll_2(u_sk, u, e_u_prime, pi_issue, biparams, u_pk['h'], c)
            return t_id, s_pub_id, pub_id
        print("user already exists")
        return None
    
    def authentication_procedure(self, customer, vendor):
        m = vendor.ver_cred_1()
        sigma_m, pub_cred, sigma_pub_cred = customer.show_cred_1(m)
        assert vendor.ver_cred_2(pub_cred, sigma_pub_cred, m, sigma_m)
        return customer, vendor
        
    def bootstrap_procedure(self, k, n, vendor):
        params, (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list = vendor.setup(k, n)
        (G, p, g0, _) = params
        bootstrap_users = []
        pub_creds_encr = []

        users = []
        pub_ids = []
        pub_creds = []

        # generate pub_creds for each user
        for i in range(n+1):
            c = Customer(str(1), vendor, params, iparams, y_sign, y_encr, k, n)
            t_id, sigma_pub_id, pub_id = self.enroll_procedure(str(i), vendor, c)
            assert verify(G, p, g0, *sigma_pub_id, y_sign, [(str(i), pub_id)])
            pub_cred = c.cred_sign_1()
            bootstrap_users.append({"user": c, "t_id": t_id, "pub_id": pub_id, "pub_cred": pub_cred})
            pub_creds_encr.append(pub_cred[0])

            # For external tests
            users.append(c)
            pub_ids.append(pub_id)
            pub_creds.append(pub_cred)

        # distribute pub_id for each user
        for bootstrap_user in bootstrap_users:
            user = bootstrap_user['user']
            t_id = bootstrap_user['t_id']
            pub_id = bootstrap_user['pub_id']
            pub_cred = bootstrap_user['pub_cred']

            requester_commit = user.data_dist_1()
            issuer_random = vendor.data_dist_1(pub_cred)
            requester_random, E_list, C_list, proof, group_generator = user.data_dist_2(issuer_random, pub_creds_encr)
            custodian_list = vendor.data_dist_2(requester_commit, requester_random, pub_creds_encr, E_list, C_list, proof, group_generator, pub_cred)

            assert custodian_list is not None
            assert pub_cred[0] not in custodian_list  # Verify that we are not a custodian of ourself

            # Anonymous auth:
            sigma, pi_show, z = user.anon_auth(t_id)
            assert vendor.anon_auth(sigma, pi_show)
            (u2, cl, _) = sigma

            # Proof of eq id:
            y, c, gamma = user.eq_id(u2, group_generator, z, cl, C_list[0])
            assert vendor.eq_id(u2, group_generator, y, c, gamma, cl, C_list[0])
            # Fixme: message to user so that it knows that it can submit credentails (anonymously)

            # Cred signing:
            sigma_pub_cred = vendor.cred_sign(pub_cred)
            assert user.cred_sign_2(sigma_pub_cred)
            (sigma_y_e, sigma_y_s) = sigma_pub_cred
            assert verify(G, p, g0, *sigma_y_e, y_sign, [pub_cred[0]])
            assert verify(G, p, g0, *sigma_y_s, y_sign, [pub_cred[1]])

        return sys_list, user_list, cred_list, rev_list, users, pub_creds, pub_ids

    def revoke_procedure(self, issuer, rev_list, customers, pub_cred_to_revoke):
        issuer.get_rev_data(pub_cred_to_revoke)
        assert rev_list.peek() is not None
        # Users polling rev_list and answering if applicable

        for customer in customers:
            responses = customer.curl_rev_list(rev_list)
            for (pub_cred_revoked, (pub_cred_answerer, response)) in responses:
                issuer.get_response(pub_cred_revoked, pub_cred_answerer, response)

        # answer = issuer.restore(bootstrap_users[0]['pub_cred'])
        # assert answer is not None
        # assert answer == bootstrap_users[0]['pub_id']

        return issuer.restore(pub_cred_to_revoke)