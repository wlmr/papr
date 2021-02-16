
from charm.toolbox.ecgroup import ECGroup as ec_group
#from petlib.bn import Bn
#from petlib.ec import EcGroup, EcPt

def gen_params(size):
    Gp = ec_group() # FIXME: Is this correct?
    Gp.paramgen(size)
    g = group1.randomGen()
    G = Gp.p
    q = Gp.q

    return (Gp, G, q)
    