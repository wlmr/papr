from papr.issuer import Issuer
from bit import PrivateKeyTestnet, wif_to_key
from pickle import dump, load
from json import dumps
from hashlib import sha256


class Vendor(Issuer):
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
            self.registry = {}  # swap to cred_list
        except EOFError:
            self.registry = {}  # swap to cred_list
        wif_file.close()
        Issuer.__init__(self)

    def __del__(self):
        registry_file = open("data/vendor-registry", "wb")
        dump(self.registry, registry_file)
        registry_file.close()

    def register_key(self, pub_key, address):
        self.registry[address] = pub_key

    def is_valid_address(self, address):
        return address in self.registry.keys()  # TODO: make registry correspond to cred_list

    def send(self, address, amount, currency):
        output = [(address, amount, currency)]
        return self.key.send(output)

    def publish_hash(self, ledger):
        b = dumps(ledger).encode("utf-8")
        m = sha256(b).hexdigest()
        self.txnid = self.key.send([(self.key.address, 1, "satoshi")], message=m, message_is_hex=True)

    def get_address(self):
        return self.key.address

    def get_balance(self, currency):
        return self.key.balance_as(currency)
