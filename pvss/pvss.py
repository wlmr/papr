#!/usr/bin/env python3

from typing import Any
from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt
import pvss.cpni as cpni

# A = tuple[Bn, Bn]
encrypted_share_type = Bn
encrypted_shares_type = list[encrypted_share_type]
commitments_type = list[Bn]
pub_keys_type = list[Bn]
# proof_type = dict[{'c': Bn}, {'r_list': list[Bn]}, {'a_1_list': list[Bn]}, {'a_2_list': list[Bn]}]
proof_type = dict[str, Any]
share_type = Bn
single_proof_type = dict[str, Bn]
generator_type = EcPt
# secret_type = Bn
decrypted_share_type = Bn
decrypted_shares_list_type = list[decrypted_share_type]
index_list_type = list[Bn]


def distribute_secret(pub_keys: pub_keys_type, secret: Bn, p: Bn, k: int, n: int, Gq: EcGroup) -> tuple[encrypted_shares_type, commitments_type,
                                                                                                        proof_type, generator_type]:
    '''
    Generates encrypted shares, commitments, proof and a random generator of Gq. Given secret, n public keys of participants who will hold the secret.
    k participants (out of n) can then later recreate (secret * G).
    Lists of encrypted shares and commitments will be returned in same order the public keys was sent in.
    '''
    assert len(pub_keys) == n
    h = p.random() * Gq.hash_to_point(b'h')
    px = gen_polynomial(k, secret, p)
    commitments = get_commitments(h, px)
    shares_list = calc_shares(px, k, n, p)
    enc_shares = __get_encrypted_shares(pub_keys, shares_list)
    proof = cpni.DLEQ_prove_list(p, h, commitments, enc_shares, pub_keys, shares_list)
    return enc_shares, commitments, proof, h


def verify_encrypted_shares(encrypted_shares: encrypted_shares_type, commitments: commitments_type, pub_keys: pub_keys_type, proof: proof_type,
                            h: generator_type, p) -> bool:
    '''
    Verifies that encrypted shares and commitments represents the same data using proof. Note: encrypted shares, commitments and pub_keys must
        be original order.
    '''
    assert len(encrypted_shares) == len(pub_keys)
    return cpni.DLEQ_verify_list(p=p, g=h, y_list=pub_keys, C_list=commitments, Y_list=encrypted_shares, proof=proof)


def reconstruct(decrypted_list: decrypted_shares_list_type, index_list: index_list_type, p) -> Bn:
    '''
    Reconstructs (secret * G) given at least k decrypted shares, along with their indexes (starting from 1!) as the respective public keys was originally
        sent into distrubute_secret.
    '''
    assert len(decrypted_list) == len(index_list)
    return decode(decrypted_list, index_list, p)


def verify_decryption_proof(proof_of_decryption: single_proof_type, decrypted_share: decrypted_share_type, encrypted_share: encrypted_share_type,
                            pub_key: pub_keys_type, p, g0) -> bool:
    '''
    Verifies that a participant has correctly decrypted their share
    '''
    return verify_correct_decryption(decrypted_share, encrypted_share, proof_of_decryption, pub_key, p, g0)

# __DEPRECATED__


def gen_proof(params, k, n, secret, pub_keys):
    '''
    Generate polynomial and proof
    '''
    assert n > k
    assert len(pub_keys) == n
    (Gq, p, g0, h) = params

    px = gen_polynomial(k, secret, p)
    commitments = get_commitments(h, px)
    shares_list = calc_shares(px, k, n, p)
    enc_shares = __get_encrypted_shares(pub_keys, shares_list)

    pub = {'C_list': commitments, 'Y_list': enc_shares}

    # params = (Gq, p, g, G)
    proof = cpni.DLEQ_prove_list(p, h, commitments, enc_shares, pub_keys, shares_list)

    # Debug:
    assert len(px) == k
    assert len(commitments) == k
    assert len(shares_list) == n
    assert shares_list[0] != secret  # I think this is correct
    assert len(enc_shares) == n

    return pub, proof


def gen_polynomial(k: int, secret: Bn, p) -> list[Bn]:
    '''
    Generate polynomial
    '''
    px_rand = [p.random() for i in range(k-1)]
    px = [secret] + px_rand
    return px


def calc_shares(px: list[Bn], k: int, n: int, p: Bn):
    '''
    Calculates p(j) for all j (0,n)
    '''
    return [__calc_share(px, k, Bn(i), p) for i in range(1, n + 1)]


def __calc_share(px: list[Bn], k: int, x: Bn, p: Bn):
    '''
    Calculates p(x)
    '''
    assert len(px) == k
    result = 0
    for (alpha, j) in zip(px, range(k)):
        result = (result + alpha * (x**j)) % p
    return result


def get_commitments(h, px):
    '''
    Calculates all commitments C_j for j =[0,k)
    '''
    return [p_i * h for p_i in px]


def __get_encrypted_shares(pub_keys: pub_keys_type, shares: list[share_type]) -> encrypted_shares_type:
    '''
    Calculates the encrypted shares Y_i for all i in (1,n)
    '''
    assert len(pub_keys) == len(shares)
    # FIXME: Should we have mod p
    Y_i_list = [(shares[i]) * y_i for (y_i, i)
                in zip(pub_keys, range(len(pub_keys)))]
    return Y_i_list


def decode(S_list, index_list, p):
    '''
    Calculates secret from participants decrypted shares
    '''
    assert len(S_list) == len(index_list)

    ans = __lagrange(index_list[0], index_list, p) * S_list[0]
    for (S_i, i) in zip(S_list[1:], range(1, len(S_list))):
        ans = ans + __lagrange(index_list[i], index_list, p) * S_i
    return ans  # g0**s


def __lagrange(i, index_list, p):
    '''
    Calculate lagrange coefficient
    '''
    top = Bn(1)
    bottom = Bn(1)
    for j in index_list:
        if j != i:
            top = (top * j)
            bottom = (bottom * (j-i))
    return top.mod_mul(bottom.mod_inverse(p), p)


def verify_correct_decryption(S_i, Y_i, decrypt_proof, pub_key, p, G):
    '''
    Verifies the participants proof of correct decryption of their share
    '''
    # params = (Gq, p, g, G)
    return cpni.DLEQ_verify_single(p, G, S_i, pub_key, Y_i, decrypt_proof)


def batch_verify_correct_decryption(proved_decryptions, Y_list, pub_keys, p, G):
    '''
    Verify all participants decryption of shares
    '''
    for ((S_i, decrypt_proof), Y_i, pub_key) in zip(proved_decryptions, Y_list, pub_keys):
        if verify_correct_decryption(S_i, Y_i, decrypt_proof, pub_key, p, G) is False:
            return False
    return True


def helper_generate_key_pair(params):
    '''
    Generates a key-pair, returns both the private key and the public key
    '''
    (_, p, g0, g1) = params
    x_i = p.random()
    y_i = x_i * g0
    return (x_i, y_i)


def participant_decrypt(params, x_i, Y_i):
    '''
    Decrypt a encrypted share with stored private key
    '''
    (_, p, _, _) = params
    return x_i.mod_inverse(p) * Y_i


def participant_decrypt_and_prove(params, x_i, Y_i) -> tuple[decrypted_share_type, single_proof_type]:
    '''
    Decrypts a encrypted share with stored private key, and generates proof of it being done correctly.
    '''
    (_, p, g0, _) = params
    S_i = participant_decrypt(params, x_i, Y_i)

    y_i = x_i * g0

    decrypt_proof = cpni.DLEQ_prove(params, g0, S_i, y_i, Y_i, x_i)
    return S_i, decrypt_proof


def get_pub_key(params, x_i):
    (_, _, g0, _) = params
    y_i = x_i * g0
    return y_i
