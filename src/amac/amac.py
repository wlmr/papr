from petlib.ec import EcGroup
from petlib.bn import Bn

from mac_ddh import setup as setup_ddh
from mac_ddh import keygen
from mac_ddh import mac
from elgamal import ElGamal


def setup(k):
    """
    Returns params := (G,p,g,h)
    """
    return setup_ddh(k)

def cred_keygen(params,n):
    (_,p,g,h) = params
    (sk, iparams) = keygen(params, n)
    sk['x_tilde'], sk['y_tilde'], sk['z_tilde'] = p.random(), p.random(), p.random()
    iparams['c_x_0'] = (sk['x0']*g) + (sk['x_tilde']*h)
    iparams['c_y_0'] = (sk['y0']*g) + (sk['y_tilde']*h)
    iparams['c_z']   = (sk['z'] *g) + (sk['z_tilde']*h)
    return (sk,iparams)

def blind_issue(params, sk, S):
    pass

def blind_obtain(params, iparams, m):
    (G,p,g,h) = params
    el = ElGamal(params)
    (pk,sk) = el.keygen()
    d = sk['x']
    gamma = pk['h']
    M = Bn.from_binary(m) * g
    (e,r) = el.encrypt(pk, M)
    # send e to issuer along with a proof of knowledge of r,m





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
    params = setup(100)
    (sk,iparams) = cred_keygen(params,1)
    m = b"DreadPirateRoberts"
    blind_obtain(params, iparams, m)