from papr.papr_issuer import Issuer
from bit import PrivateKeyTestnet, wif_to_key
from pickle import dump, load


class Vendor():
    def __init__(self):
        try:
            wif_file = open("data/vendor-key", "r")
            wif = wif_file.read()
            self.key = wif_to_key(wif)
            registry_file = open("data/vendor-registry", "rb")
            self.registry = load(registry_file)
            registry_file.close()
        except FileNotFoundError:
            wif_file = open("data/vendor-key", "w")
            self.key = PrivateKeyTestnet()
            wif_file.write(self.key.to_wif())
        except EOFError:
            self.registry = {}
        wif_file.close()

    def __del__(self):
        registry_file = open("data/vendor-registry", "wb")
        dump(self.registry, registry_file)
        registry_file.close()

    def is_valid_address(self, address):
        return address in self.registry.keys()  # TODO: make registry correspond to cred_list

    def send(self, address, amount, currency):
        output = [(address, amount, currency)]
        return self.key.send(output)

    def get_address(self):
        return self.key.address

    def get_balance(self, currency):
        return self.key.balance_as(currency)
