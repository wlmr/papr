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
    Psuedorandom number-generator.
    """
    return int(hash([u_random, i_random, counter]) % p)

def gen_list_of_random_numbers(u_random, i_random, length, p, max_number):
    answerlist = []
    if length > max_number:
        return None
    else:
        i = 0
        while True:
            rnd = prng(u_random, i_random, i, p) % max_number
            if rnd not in answerlist:
                answerlist.append(rnd)
                if len(answerlist) == length:
                    return answerlist
            i += 1
            
