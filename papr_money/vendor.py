from papr.issuer import Issuer
from bit import PrivateKeyTestnet, wif_to_key
from pickle import dump, load
from json import dumps
from hashlib import sha256
from papr.utils import pub_key_to_addr


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
        self.hashes = {'sys_list': [0], 'user_list': [0], "cred_list": [0], "rev_list": [0]}  # TODO: continue on this thought

    def __del__(self):
        registry_file = open("data/vendor-registry", "wb")
        dump(self.registry, registry_file)
        registry_file.close()

    def cred_sign(self, pub_cred):
        self.registry[pub_key_to_addr(pub_cred[1])] = pub_cred[1]
        return super().cred_sign(pub_cred)
    
    def is_valid_address(self, address):
        return address in self.registry
    
    def send(self, address, amount, currency):
        output = [(address, amount, currency)]
        return self.key.send(output)

    def publish_hash(self, ledger):
        b = dumps([ledger, self.hashes[ledger]]).encode("utf-8")
        m = sha256(b).hexdigest()
        self.hashes[ledger].append(m)
        self.txnid = self.key.send([(self.key.address, 1, "satoshi")], message=m, message_is_hex=True)

    def get_address(self):
        return self.key.address

    def get_balance(self, currency):
        return self.key.balance_as(currency)

