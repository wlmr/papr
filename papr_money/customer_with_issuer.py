from papr.user_with_issuer import UserWithIssuer as User
from papr.utils import bit_privkey_to_petlib_bn
from bit import PrivateKeyTestnet, wif_to_key


class Customer(User):
    def __init__(self, name: str, bank, login_interval=0):
        self.name = name.replace(' ', '-').lower()
        self.login_interval = login_interval
        self.nbr_logins = 0
        try:
            wif_file = open(f"data/customer_keys/{name}-key", "r")
            wif = wif_file.read()
            self.key = wif_to_key(wif)
        except FileNotFoundError:
            wif_file = open(f"data/customer_keys/{name}-key", "w")
            self.key = PrivateKeyTestnet()
            wif_file.write(self.key.to_wif())
        wif_file.close()
        x_sign = bit_privkey_to_petlib_bn(self.key._pk)
        super().__init__(name, bank, x_sign)

    def send(self, address, amount, currency):
        if self.issuer.is_valid_address(address):
            output = [(address, amount, currency)]
            return self.key.send(output)
        else:
            return None

    def get_address(self):
        return self.key.address

    def get_balance(self, currency: str):
        return self.key.get_balance(currency)
