from typing import Any
from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt
import pvss.pvss.cpni as cpni
import pvss.pvss.pvss as pvss


encrypted_share_type = Bn
encrypted_shares_type = list[encrypted_share_type]
commitments_type = list[Bn]
pub_keys_type = list[Bn]
proof_type = dict[str, Any]
share_type = Bn
single_proof_type = dict[str, Bn]
generator_type = EcPt
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
    px = pvss.gen_polynomial(k, secret, p)
    commitments = pvss.get_commitments(h, px)
    shares_list = pvss.calc_shares(px, k, n, p)
    enc_shares = pvss.__get_encrypted_shares(pub_keys, shares_list)
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
    Recontructs (secret * G) given at least k decrypted shares, along with their indexes (starting from 1!) as the respective public keys was originaly
        sent into distrubute_secret.
    '''
    assert len(decrypted_list) == len(index_list)
    return pvss.decode(decrypted_list, index_list, p)


def verify_decryption_proof(proof_of_decryption: single_proof_type, decrypted_share: decrypted_share_type, encrypted_share: encrypted_share_type,
                            pub_key: pub_keys_type, p, g0) -> bool:
    '''
    Verifyes that a participant has correctly decrypted their share
    '''
    return pvss.verify_correct_decryption(decrypted_share, encrypted_share, proof_of_decryption, pub_key, p, g0)


def participant_decrypt_and_prove(params, x_i, encrypted_share):
    return pvss.participant_decrypt_and_prove(params, x_i, encrypted_share)

def helper_generate_key_pair(params):
    return pvss.helper_generate_key_pair(params)