from papr.papr_issuer import Issuer
from bit import PrivateKeyTestnet
from pickle import dump, load 


class Vendor(Issuer):
    def __init__(self):
        self.cred_list
        try:
            wip_file = open("vendor-key", "r")
            wip = wip_file.read()
            self.key = PrivateKeyTestnet(wip)
        except FileNotFoundError:
            wip_file = open("vendor-key", "w")
            self.key = PrivateKeyTestnet()
            wip_file.write(self.key.to_wif)
        wip_file.close()

    def is_valid_address(self, address):
        return address in self.cred_list

    def send(self, address, amount, currency):
        output = [(address, amount, currency)]
        return self.key.send(output)

    def get_address(self):
        return self.key.address
   
    def get_balance(self, currency):
        return self.key.balance_as(currency)