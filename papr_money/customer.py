from papr.user import User
from papr.utils import bit_privkey_to_petlib_bn
from bit import PrivateKeyTestnet, wif_to_key


class Customer(User):
    def __init__(self, name: str, vendor, params, iparams, y_sign, y_encr, k, n):
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
        # self.notify_vendor(vendor, self.key.public_key, self.key.address)
        x_sign = bit_privkey_to_petlib_bn(self.key._pk)
        User.__init__(self, params, iparams, y_sign, y_encr, k, n, x_sign)

    # def notify_vendor(self, vendor, pub_key, address):
    #     vendor.register_key(pub_key, address)

    def send(self, address, amount, currency, vendor):
        if vendor.is_valid_address(address):
            output = [(address, amount, currency)]
            return self.key.send(output)

    def get_address(self):
        return self.key.address

    def get_balance(self, currency: str):
        return self.key.get_balance(currency)
