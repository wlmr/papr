from papr.papr_user import User
from bit import PrivateKeyTestnet


class Customer(User):
    def __init__(self):
        try:
            wip_file = open("key", "r")
            wip = wip_file.read()
            self.key = PrivateKeyTestnet(wip)
        except FileNotFoundError:
            wip_file = open("key", "w")
            self.key = PrivateKeyTestnet()
            wip_file.write(self.key.to_wif)
        wip_file.close()

    def send(self, address, amount, currency):
        output = [(address, amount, currency)]
        return self.key.send(output)

    def get_address(self):
        return self.key.address
   
    def get_balance(self, currency):
        return self.key.balance_as(currency)

