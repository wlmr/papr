
from papr_money.vendor import Vendor
from papr_money.customer import Customer


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
 