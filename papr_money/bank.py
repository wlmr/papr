from papr.issuer import Issuer
from bit import PrivateKeyTestnet, wif_to_key
from pickle import dump, load
from json import dumps
from papr.ecdsa import sign
from hashlib import sha256
from papr.utils import pub_key_to_addr
from petlib.ec import EcGroup, EcPt


class Bank(Issuer):
    def __init__(self):
        Issuer.__init__(self)
        self.registry = {}
        self.hashes = {'sys_list': [0], 'user_list': [0], "cred_list": [0], "rev_list": [0]}  # TODO: continue on this thought
        try:
            with open("data/bank-key", "r") as file:
                wif = file.read()
                self.key = wif_to_key(wif)
        except FileNotFoundError:
            with open("data/bank-key", "w") as file:
                self.key = PrivateKeyTestnet()
                file.write(self.key.to_wif())
    #     try:
    #         with open("data/bank-registry", "rb") as file:
    #             G = EcGroup(714)
    #             byte_dict = load(file)
    #             self.registry = {address: EcPt.from_binary(byte_string, G) for address, byte_string in byte_dict.items()}
    #     except (FileNotFoundError, EOFError):
    #         self.registry = {}

    # def __del__(self):
    #     with open("data/bank-registry", "wb") as file:
    #         dump({address: pub_key.export() for address, pub_key in self.registry.items()}, file)

    #def cred_sign(self, pub_cred):
    #    """
    #    Overloading users cred_sign to also fill up registry dictionary
    #    """
    #    self.registry[pub_key_to_addr(pub_cred[1])] = pub_cred[1]
    #    return super().cred_sign(pub_cred)

    def cred_sign(self, pub_cred):
        """
        Adds pub_cred to cred_list, in effect giving the pub_cred its blessing,
        and making it an official pub_cred. Also returns signatures on the pub_cred to the user.
        """
        (_, p, g0, _) = self.params
        escrow_shares = self.temp_creds[pub_cred]['escrow_shares']
        custodian_encr_keys = self.temp_creds[pub_cred]['custodians']
        del self.temp_creds[pub_cred]
        self.rev_data[pub_cred] = (escrow_shares, custodian_encr_keys)
        sigma_y_e = sign(p, g0, self.x_sign, [pub_cred[0]])
        sigma_y_s = sign(p, g0, self.x_sign, [pub_cred[1]])
        self.ledger_add(self.cred_list, pub_cred)

        hash_val = self.cred_list.last_hash()
        #if hash_val is not None:
        #    self.publish_hash(hash_val) # CRSTES ODD ERRORS
        self.res_list[pub_cred] = {k: None for k in custodian_encr_keys}
        return (sigma_y_e, sigma_y_s)



    def is_valid_address(self, address):
        return address in self.registry

    def send(self, address, amount, currency):
        output = [(address, amount, currency)]
        return self.key.send(output)

    #def publish_hash(self, ledger):
    #    b = dumps([ledger, self.hashes[ledger]]).encode("utf-8")
    #    m = sha256(b).hexdigest()
    #    (_, p, g0, _) = self.params
    #    r, s = sign(p, g0, self.x_sign, [m])
    #    self.hashes[ledger].append(m)
    #    self.txnid = self.key.send([(self.key.address, 1, "satoshi")], message=m+f"({r},{s})", message_is_hex=True)

    def publish_hash(self, hash):
        m = hash.hex()
        (_, p, g0, _) = self.params
        r, s = sign(p, g0, self.x_sign, [m])
        self.txnid = self.key.send([(self.key.address, 1, "satoshi")], message=m+f"({r},{s})", message_is_hex=True)

    def get_address(self):
        return self.key.address

    def get_balance(self, currency):
        return self.key.balance_as(currency)


