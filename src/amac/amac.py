from charm.toolbox.integergroup import IntegerGroup
#from charm.schemes.pkenc.pkenc_elgamal85 import *

from mac_ddh import setup as setup_ddh
from mac_ddh import keygen as keygen
from mac_ddh import mac as mac

from elgamal import *

def setup(k):
    return setup_ddh(k)

def cred_keygen(params,n):
    (G,p,g,h) = params
    (sk, iparams) = keygen(params, n)
    sk['x_tilde'], sk['y_tilde'], sk['z_tilde'] = G.random(), G.random(), G.random()
    iparams['c_x_0'] = (g**sk['x0']) * (h**sk['x_tilde'])
    iparams['c_y_0'] = (g**sk['y0']) * (h**sk['y_tilde'])
    iparams['c_z']   = (g**sk['z'])  * (h**sk['z_tilde'])
    return (sk,iparams)

def blind_issue(params, sk, S):
    pass

def blind_obtain(params, iparams, m):
    (G,p,g,h) = params
    el = Elgamal(params)
    (pk,sk) = el.keygen()
    d = sk['x']
    gamma = pk['h']
    M = g ** (G.encode(m))
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

def test():
    setup(k)
    blind_issue(1,2)