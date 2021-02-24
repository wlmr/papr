from typing import Tuple

from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn

from amac.mac_ggm import PointDict, setup as setup_ggm
from amac.mac_ggm import keygen as keygen_ggm
from amac.proofs import *
from amac.elgamal import ElGamal

Params = Tuple[EcGroup, Bn, EcPt, EcPt]

def setup(k: int) -> Params:
    """
    TODO: should take a number k that determins the number of bits of the 
    field underlying the EC. 
    Returns params := (G,p,g,h)
    """
    return setup_ggm(k)

def cred_keygen(params: Params, n: int) -> Tuple[dict[str,Bn],dict[str,Bn]]:
    """
    Run by issuer to generate issuer secret key and public issuer parameters iparams.
    """
    (_,p,g,h) = params
    (i_sk, iparams) = keygen_ggm(params,n)
    i_sk['x0_tilde'] = p.random()
    iparams['Cx0'] = i_sk['x0'] * g + i_sk['x0_tilde'] * h
    return (iparams,i_sk)


def prepare_blind_obtain(params: Params, m: bytes):
    """
    User asks for credential.
    1. Generate elgamal keypair,
    2. encrypt each attribute multiplied by g,
    with the elgamal key with some random r, as according to elgamal,
    3. sends the encryption E along with proof of knowledge of r and m to issuer.
    """
    (_,p,g,_) = params
    el = ElGamal(params)
    (user_pk,user_sk) = el.keygen()
    gamma = user_pk['h']
    M = p.from_binary(m)
    (ciphertext,r) = el.encrypt(user_pk, M)
    pi_prepare_obtain = make_pi_prepare_obtain(params, gamma, ciphertext, r, M)
    return (user_sk, user_pk, ciphertext, pi_prepare_obtain)


def blind_issue(params, iparams, i_sk, gamma, ciphertext, pi_prepare_obtain):
    """
    Carried out by issuer.
    1. Chooses a random b and computes u = g^b,
    2. rearanges e to e'_u' as described in the paper,
    3. sends (u, e'_u') and proof of knowledge of x's x_tilde, b and r back to
     the user.
    """
    assert verify_pi_prepare_obtain(params, gamma, ciphertext, pi_prepare_obtain)
    (_,p,g,_) = params
    b = p.random()
    u = b * g
    bsk =      {'b'+k: (b * v) % p for (k,v) in i_sk.items()}
    biparams = {'b'+k:  b * v      for (k,v) in iparams.items()}
    r = p.random()
    e1 = r * g     + b *  i_sk['x1'] * ciphertext['c1']
    e2 = r * gamma + b * (i_sk['x0'] * g + i_sk['x1'] * ciphertext['c2'])
    e_u_prime = { 'c1':e1, 'c2':e2 }
    pi_issue = make_pi_issue(params, i_sk, iparams, gamma, ciphertext, b, bsk, r)
    return (u, e_u_prime, pi_issue, biparams)


def blind_obtain(params, iparams, u_sk, u, e_u_prime, pi_issue, biparams=None, 
    gamma=None, ciphertext={}):
    """
    Carried out by user.
    1. verifies pi_issue,
    2. user decrypts e_prime to get u_prime. Credential is (u,u_prime).
    """
    assert verify_pi_issue(params, iparams, u, e_u_prime, pi_issue, 
        biparams, gamma, ciphertext)
    el = ElGamal(params)
    return (u, el.decrypt(u_sk, e_u_prime))


def blind_show(params, iparams, cred, M):
    """
    Carried out by user who wants to prove possession of a credential by:
    1. generate three random values: r, z, a,
    2. randomize credential with a,
    3. computes commitments Cm and Cu_prime and sends the "signature" sigma 
    and a proof of the signature's correctness.
    """
    (_, p, g, h) = params
    m = p.from_binary(M)
    (r,z,a) = (p.random(), p.random(), p.random())
    (u0, u0_prime) = cred
    assert u0 and u0_prime
    (u, u_prime) = (a * u0, a * u0_prime)
    Cm = m * u + z * h
    Cu_prime = u_prime + r * g
    sigma = (u, Cm, Cu_prime)
    pi_show = make_pi_show(params, iparams, m, r, z, sigma)
    return (sigma, pi_show)


def show_verify(params, iparams, i_sk, sigma, pi_show):
    """
    Verifies a request for a blind_show.
    """
    assert iparams and sigma and pi_show
    (u,Cm,Cu_prime) = sigma
    assert u and Cm and Cu_prime
    V = (i_sk['x0'] * u + i_sk['x1'] * Cm) - Cu_prime
    return verify_pi_show(params, iparams, sigma, pi_show, V)