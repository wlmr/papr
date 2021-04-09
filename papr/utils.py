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
