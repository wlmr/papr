from papr.papr_user import User
from bit import PrivateKeyTestnet, wif_to_key


class Customer(User):
    def __init__(self, id: str, vendor):
        self.vendor = vendor
        id = id.replace(' ', '-').lower()
        try:
            wif_file = open(f"data/{id}-key", "r")
            wif = wif_file.read()
            self.key = wif_to_key(wif)
        except FileNotFoundError:
            wif_file = open(f"data/{id}-key", "w")
            self.key = PrivateKeyTestnet()
            wif_file.write(self.key.to_wif())
        wif_file.close()
        self.notify_vendor(self.key.public_key, self.key.address)

    def notify_vendor(self, pub_key, address):
        self.vendor.register_key(pub_key, address)

    def send(self, address, amount, currency, vendor):
        if vendor.is_valid_address(address):
            output = [(address, amount, currency)]
            return self.key.send(output)

    def get_address(self):
        return self.key.address

    def get_balance(self, currency: str):
        return self.key.get_balance(currency)
