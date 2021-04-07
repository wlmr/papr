
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
        customer = Customer("josip tito", vendor)
        assert float(customer.get_balance("btc")) > 0

    def test_customer_consitent(self):
        vendor = Vendor()
        customer = Customer("josip tito", vendor)
        addr1 = customer.get_address()
        customer2 = Customer("josip tito", vendor)
        addr2 = customer2.get_address()
        assert addr1 == addr2

    #def test_send(self):
    #    vendor = Vendor()
    #    customer = Customer("josip tito", vendor)#
    #
    #    customer2 = Customer("Markos Hauer", vendor)  # Random name
    #
    #
    #    addr1 = customer.send()
  

    