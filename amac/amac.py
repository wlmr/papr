from typing import Tuple

from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn

from amac.mac_ggm import PointDict, setup as setup_ggm
from amac.mac_ggm import keygen as keygen_ggm
from amac.mac_ggm import mac 
from amac.elgamal import ElGamal
from amac.proofs import *

Params = Tuple[EcGroup, Bn, EcPt, EcPt]

def setup(k: int) -> Params:
    """
    TODO: should take a number k that determins the number of bits of the field underlying the EC. 
    Returns params := (G,p,g,h)
    """
    return setup_ggm(k)

def cred_keygen(params,n) -> Tuple[dict[str,Bn],dict[str,Bn]]:
    (_,p,g,h) = params
    (sk, iparams) = keygen_ggm(params,n)
    sk['x0_tilde'] = p.random()
    iparams['C_x_0'] = sk['x0'] * g + sk['x0_tilde'] * h
    return (iparams,sk)


def prepare_blind_obtain(params: Params, iparams: PointDict, m: bytes):
    """
    user asks for credential (prepare_blind_obtain(gamma,m) -> E,obtainer_proof)
    1. generate elgamal keypair
    2. encrypt each attribute multiplied by g with the elgamal key with some random r, as according to elgamal
    3. sends the encryption E along with proof of knowledge of r and m to issuer
    """
    (_,_,g,_) = params
    el = ElGamal(params)
    (pk,sk) = el.keygen()
    d = sk['x']
    gamma = pk['h']
    M = Bn.from_binary(m) * g
    (e,r) = el.encrypt(pk, M)
    pi_prepare_obtain = make_pi_prepare_obtain(params, gamma, e, r, M)
    return (e, pi_prepare_obtain, d)


def blind_issue(params, sk, e, pi_prepare_obtain):
    """
    Carried out by issuer
    1. chooses a random b and computes u = g^b
    2. rearanges e to e'_u' as described in the paper
    3. sends (u, e'_u') and proof of knowledge x's x_tilde, b and r back to the user
    """
    pass

def blind_obtain(u, e_prime, pi_issue):
    """
    Carried out by user
    1. verifies pi_issue
    2. user decrypts e_prime to get u_prime,
     credential is (u,u_prime)
    """
    pass




#def show(params, iparams, cred, m, phi):
#    (G,p,g,h) = params
#    (C_x_o, X) = iparams
#    r = G.random()
#    z = G.random()
#
#    ## z is a vector, X is a vector. But since we only have one message we only need one z (and one X?)
#
#
#
#    (u, u_prime) = cred
#    C_m = u**m * h**z
#    C_u_prime = u_prime * g**r
#    sigma = (u, C_m, C_u_prime)
#    
#    # V is here calulated according to GGM, but with -r instead as in DDH. Is it correct for DDH
#    V = g**(-r) * X**z 
#    ## FIXME: ??
#    #c = hash(params + C_m + C_u_prime + )
#
#    #z = [G.random for x in range(len(m))] # Not necessary since len(m) ==1
    pass

def show_verify(sk, phi):
    pass

if __name__ == "__main__":
    params = setup(1)
    (sk,iparams) = cred_keygen(params,1)
    m = b"DreadPirateRoberts"
    el = ElGamal(params)
    (pk,sk) = el.keygen()
    d = sk['x']
    gamma = pk['h']