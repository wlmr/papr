from papr.user import User
from papr.utils import bit_privkey_to_petlib_bn
from bit import PrivateKeyTestnet, wif_to_key


class Customer(User):
    def __init__(self, name: str, bank, params, iparams, y_sign, y_encr, k, n):
        name = name.replace(' ', '-').lower()
        self.name = name
        try:
            wif_file = open(f"data/{name}-key", "r")
            wif = wif_file.read()
            self.key = wif_to_key(wif)
        except FileNotFoundError:
            wif_file = open(f"data/{name}-key", "w")
            self.key = PrivateKeyTestnet()
            wif_file.write(self.key.to_wif())
        wif_file.close()
        x_sign = bit_privkey_to_petlib_bn(self.key._pk)
        User.__init__(self, params, iparams, y_sign, y_encr, k, n, x_sign)

    def send(self, address, amount, currency, bank):
        if bank.is_valid_address(address):
            output = [(address, amount, currency)]
            return self.key.send(output)
        else:
            return None

    def get_address(self):
        return self.key.address

    def get_balance(self, currency: str):
        return self.key.get_balance(currency)
