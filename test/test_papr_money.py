from papr_money.bank import Bank
from papr_money.customer import Customer
from papr.ecdsa import verify
import pytest
from papr.utils import pub_key_to_addr
from bit import PrivateKeyTestnet
from test.procedures import bootstrap_procedure, enroll_procedure, authentication_procedure, revoke_procedure
# from bit.network import NetworkAPI


class TestPaprMoney:

    # @pytest.fixture(autouse=True)
    # def run_before_and_after_tests(tmpdir):
    #     """Runs code befora and after each test"""
    #     # Setup
    #     node = NetworkAPI.connect_to_node(user='admin1', password='123', host='localhost', port='19001', use_https=False, testnet=True)

    #     yield  # Run a test
    #     # Teardown 


    def test_registry(self):
        k, n = 2, 3
        bank = Bank()
        params, (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list, customers, pub_creds, pub_ids = bootstrap_procedure(k, n, bank)

        assert cred_list.peek() is not None
        for pub_cred in cred_list.read():
            assert bank.registry[pub_key_to_addr(pub_cred[1])] == pub_cred[1]

    @pytest.mark.skip(reason="Disable since it spends money on every run.")
    def test_transaction(self):
        k, n = 2, 3
        bank = Bank()
        params, (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list, customers, pub_creds, pub_ids = bootstrap_procedure(k, n, bank)
        customer = Customer("Josip Tito", bank, params, iparams, y_sign, y_encr, k, n)
        assert float(customer.get_balance("satoshi")) > 0.0
        import pdb; pdb.set_trace()
        ans = customer.send(pub_key_to_addr(pub_creds[0][1]), 1, 'satoshi', bank)
        assert ans is not None

    def test_transaction_to_unregistered_user(self):
        not_registered_pub_addr = PrivateKeyTestnet().address
        # node = NetworkAPI.connect_to_node(user='admin1', password='123', host='localhost', port='19001', use_https=False, testnet=True)


        # node.importaddress(not_registered_pub_addr, "not_reg", True)

        k, n = 2, 3
        bank = Bank()
        params, (y_sign, y_encr), iparams, _, _, _, _ = bank.setup(2, 3)
        customer = Customer("Josip Tito", bank, params, iparams, y_sign, y_encr, k, n)
      
        # node.importaddress(customer.get_address(), "test_addr", True)

        assert float(customer.get_balance("satoshi")) > 0.0
        assert customer.send(not_registered_pub_addr, 1, 'satoshi', bank) is None

    def test_bank_persistence(self):
        bank = Bank()
        bank.registry['address1'] = 'pubkey1'
        bank.registry['address2'] = 'pubkey2'
        bank.registry['address3'] = 'pubkey3'
        pubkey1 = bank.key.public_key
        del bank
        bank = Bank()
        assert pubkey1 == bank.key.public_key
        assert bank.registry['address1'] == 'pubkey1'

    # @pytest.mark.skip(reason="Disable since github actions creates a new wallet every run. Therefore the wallet will always be empty.")
    # NOTE: give Tito more coins if this test fails
    def test_customer_balance(self):
        # node = NetworkAPI.connect_to_node(user='admin1', password='123', host='localhost', port='19001', use_https=False, testnet=True)
        
        k, n = 3, 10
        bank = Bank()
        params, (y_sign, y_encr), iparams, _, _, _, _ = bank.setup(3, 10)
        customer = Customer("Josip Tito", bank, params, iparams, y_sign, y_encr, k, n)

        # node.importaddress(customer.get_address(), "test_addr", True)

        assert float(customer.get_balance("satoshi")) > 0.0

    def test_customer_persistence(self):
        k, n = 3, 10
        bank = Bank()
        params, (y_sign, y_encr), iparams, _, _, _, _ = bank.setup(3, 10)
        customer = Customer("Josip Tito", bank, params, iparams, y_sign, y_encr, k, n)
        addr1 = customer.get_address()
        customer2 = Customer("Josip Tito", bank, params, iparams, y_sign, y_encr, k, n)
        addr2 = customer2.get_address()
        assert addr1 == addr2

    def test_new_user_procedure(self):
        k, n = 3, 5
        bank = Bank()
        params, (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list, customers, pub_creds, pub_ids = bootstrap_procedure(k, n, bank)
        authentication_procedure(customers[0], bank)
        pub_id_revealed = revoke_procedure(bank, rev_list, customers, pub_creds[3])
        for id, pub_id in user_list.read():
            if pub_id_revealed == pub_id:
                print(id)
                assert id == "3"
