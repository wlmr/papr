from hashlib import sha256
from petlib.bn import Bn
from petlib.pack import encode
import bit
from petlib.ec import EcPt


def hash(elements: list) -> Bn:
    bin_hash = sha256(encode(elements)).digest()
    return Bn.from_binary(bin_hash)


def pub_key_to_addr(pub_key):
    if isinstance(pub_key, EcPt):
        pub_key = pub_key.export()
    return bit.format.public_key_to_address(pub_key, version="test")


def bit_privkey_to_petlib_bn(key):
    return Bn.from_decimal(str(key.to_int()))


def prng(u_random, i_random, counter, p):
    """
    Pseudorandom number-generator.
    """
    return int(hash([u_random, i_random, counter]) % p)


def data_distribution_select(public_credentials, u_random, i_random, n, p, pub_cred):
    selected_data_custodians = []
    public_credentials_left = public_credentials.copy()
    
    if pub_cred[0] in public_credentials_left:
        public_credentials_left.remove(pub_cred[0])
    
    if n > len(public_credentials_left):
        return None

    for i in range(n):
        index = prng(u_random, i_random, n, p) % len(public_credentials_left)
        public_credential = public_credentials_left.pop(index)
        selected_data_custodians.append(public_credential)

    return selected_data_custodians