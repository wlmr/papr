
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

