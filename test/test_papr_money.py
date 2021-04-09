from papr_money.vendor import Vendor
from papr_money.customer import Customer
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

    @pytest.mark.skip(reason="until bootstrap is reviewed")
    def test_new_user_procedure(self):
        k, n = 3, 5
        vendor = Vendor()
        params, (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list = vendor.setup(3, 10)
        customer = Customer("Josip Tito", vendor, params, iparams, y_sign, y_encr, k, n)
        name, pub_id, (u_sk, u_pk, c, pi) = customer.req_enroll_1(customer.name)
        ret = vendor.iss_enroll(u_pk['h'], c, pi, name, pub_id)
        if ret is not None:
            s_pub_id, u, e_u_prime, pi_issue, biparams = ret
            t_id = customer.req_enroll_2(u_sk, u, e_u_prime, pi_issue, biparams, u_pk['h'], c)
        assert ret is not None

        pub_cred = customer.cred_sign_1()
        # Data dist
        requester_commit = customer.data_dist_1()
        vendor_random = vendor.data_dist_1(pub_cred)
        requester_random, E_list, C_list, proof, group_generator = customer.data_dist_2(vendor_random, pub_keys)
        custodian_list = vendor.data_dist_2(requester_commit, requester_random, pub_keys, E_list, C_list, proof, group_generator, pub_cred)
        assert custodian_list is not None

        # Anonymous auth:
        sigma, pi_show, z = customer.anon_auth(t_id)
        assert vendor.anon_auth(sigma, pi_show)

        (u2, cl, _) = sigma

        # Proof of eq id:
        y, c, gamma = customer.eq_id(u2, group_generator, z, cl, C_list[0])
        assert vendor.eq_id(u2, group_generator, y, c, gamma, cl, C_list[0])
        # Fixme message to customer so that it knows that it can submit credentails (anonimously)

        (sigma_y_e, sigma_y_s) = vendor.cred_sign(pub_cred)
        verify()


        assert cred_list.peek() == pub_cred

        # Cred usage:
        m = vendor.ver_cred_1()
        sigma_pub_cred = customer.show_cred_1(m)
        assert vendor.ver_cred_2(r, s, pub_cred, sigma_pub_cred, m)

    # Wasteful and slow test.
    # def test_send(self):
    #     vendor = Vendor()
    #     customer = Customer("Josip Tito", vendor)
    #     customer2 = Customer("Markos Hauer", vendor)  # Random name
    #     balance_before = customer2.get_balance('btc')
    #     txid = customer.send(customer2.get_address(), 1, "satoshi", vendor)
    #     sleep(60)
    #     balance_after = customer2.get_balance('btc')
    #     assert balance_after > balance_before
