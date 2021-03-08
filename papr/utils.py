from hashlib import sha256
from petlib.bn import Bn
from petlib.pack import encode


def hash(elements: list) -> Bn:
    bin_hash = sha256(encode(elements)).digest()
    return Bn.from_binary(bin_hash)
