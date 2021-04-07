from papr.papr_user import User
from bit import PrivateKeyTestnet


class Customer(User):
    def __init__(self, id):
        try:
            wip_file = open(f"{id}-key", "r")
            wip = wip_file.read()
            self.key = PrivateKeyTestnet(wip)
        except FileNotFoundError:
            wip_file = open(f"{id}-key", "w")
            self.key = PrivateKeyTestnet()
            wip_file.write(self.key.to_wif())
        wip_file.close()

    def send(self, address, amount, currency, vendor):
        if vendor.valid_address(address):
            output = [(address, amount, currency)]
            return self.key.send(output)

    def get_address(self):
        return self.key.address

    def get_balance(self, currency):
        return self.key.balance_as(currency)


