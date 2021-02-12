from charm.toolbox.integergroup import IntegerGroup

from mac_ddh import setup as setup_ddh
from mac_ddh import keygen as keygen
from mac_ddh import mac as mac

def setup(k):
    return setup_ddh(k)

def cred_keygen(params,n):
    (G,p,g,h) = params
    (sk, iparams) = keygen(params, n)
    (x_tilde, y_tilde, z_tilde) = (G.random(), G.random(), G.random())
    c_x_0 = (g**sk[0]) * (h**x_tilde)
    c_y_0 = (g**sk[2]) * (h**y_tilde)
    c_z   = (g**sk[4]) * (h**z_tilde)
    return iparams + [c_x_0]

def blind_issue(sk, S):
    pass

def blind_obtain(iparams, m):
    pass

def show(params, iparams, cred, m, phi):
    (G,p,g,h) = params
    (C_x_o, X) = iparams
    r = G.random()
    z = G.random()

    ## z is a vector, X is a vector. But since we only have one message we only need one z (and one X?)



    (u, u_prime) = cred
    C_m = u**m * h**z
    C_u_prime = u_prime * g**r
    sigma = (u, C_m, C_u_prime)
    
    # V is here calulated according to GGM, but with -r instead as in DDH. Is it correct for DDH
    V = g**(-r) * X**z 
    ## FIXME: ??
    #c = hash(params + C_m + C_u_prime + )

    #z = [G.random for x in range(len(m))] # Not necessary since len(m) ==1
    pass

def show_verify(sk, phi):
    pass