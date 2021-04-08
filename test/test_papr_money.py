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
        vendor = Vendor()
        customer = Customer("Josip Tito", vendor)
        assert float(customer.get_balance("satoshi")) > 0.0

    def test_customer_persistence(self):
        vendor = Vendor()
        customer = Customer("Josip Tito", vendor)
        addr1 = customer.get_address()
        customer2 = Customer("Josip Tito", vendor)
        addr2 = customer2.get_address()
        assert addr1 == addr2

    def test_new_user_procedure(self):
        k, n = 3, 10
        vendor = Vendor()
        (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list = vendor.setup(3, 10)
        customer = Customer("Josip Tito", vendor, vendor.get_params(), iparams, y_sign, y_encr, k, n)

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
 