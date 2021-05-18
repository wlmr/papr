from papr_money.bank import Bank
from papr_money.customer_with_issuer import Customer as CustomerWithIssuer

from papr.utils import pub_key_to_addr

class CLI:
    
    def setup(self): 
        self.k, self.n = 5, 20
        self.node = NetworkAPI.connect_to_node(user='admin1', password='123', host='localhost', port='19001', use_https=False, testnet=True)
        self.bank = Bank()
        self.node.importaddress(customer.get_address(), "Bank", True)
        self.params, (self.y_sign, self.y_encr), self.iparams, self.sys_list, self.user_list, self.cred_list, self.rev_list, self.customers, self.pub_creds, self.pub_ids = bootstrap_procedure(self.k, self.n, self.bank)
           
        #assert cred_list.peek() is not None
        #for pub_cred in cred_list.read():
        #    assert bank.registry[pub_key_to_addr(pub_cred[1])] == pub_cred[1]

    def create_user(self, name):
        import pdb; pdb.set_trace()
        added_customers = dict()
        customer = CustomerWithIssuer(name, self.bank)
        added_customers[name] = customer
        self.node.importaddress(customer.get_address(), name, True)
    

cli = CLI()
cli.setup()
cli.create_user("new user")