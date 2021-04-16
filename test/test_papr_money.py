from papr_money.vendor import Vendor
from papr_money.customer import Customer
from papr.ecdsa import verify
import pytest
from papr.utils import pub_key_to_addr
from bit import PrivateKeyTestnet
from test.procedures import bootstrap_procedure, enroll_procedure, authentication_procedure, revoke_procedure

class TestPaprMoney:

    def test_registry(self):
        k, n = 2, 3
        vendor = Vendor()
        params, (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list, customers, pub_creds, pub_ids = bootstrap_procedure(k, n, vendor)
        
        assert cred_list.peek() is not None
        for pub_cred in cred_list.read():
            assert vendor.registry[pub_key_to_addr(pub_cred[1])] == pub_cred[1]

    @pytest.mark.skip(reason="Disable since it spends money on every run.")
    def test_transaction(self):
        k, n = 2, 3
        vendor = Vendor()
        params, (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list, customers, pub_creds, pub_ids = bootstrap_procedure(k, n, vendor)
        customer = Customer("Josip Tito", vendor, params, iparams, y_sign, y_encr, k, n)
        assert float(customer.get_balance("satoshi")) > 0.0
        import pdb; pdb.set_trace()
        ans = customer.send(pub_key_to_addr(pub_creds[0][1]), 1, 'satoshi', vendor)
        assert ans is not None

    def test_transaction_to_unregisted_user(self):
        not_registered_pub_addr = PrivateKeyTestnet().address
        k, n = 2, 3
        vendor = Vendor()
        params, (y_sign, y_encr), iparams, _, _, _, _ = vendor.setup(2, 3)
        customer = Customer("Josip Tito", vendor, params, iparams, y_sign, y_encr, k, n)
        
        assert float(customer.get_balance("satoshi")) > 0.0
        assert customer.send(not_registered_pub_addr, 1, 'satoshi', vendor) is None
       
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
        params, (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list, customers, pub_creds, pub_ids = bootstrap_procedure(k, n, vendor)
        authentication_procedure(customers[0], vendor)
        pub_id_revealed = revoke_procedure(vendor, rev_list, customers, pub_creds[3])
        for id, pub_id in user_list.read():
            if pub_id_revealed == pub_id:
                print(id)
                assert id == "3"
