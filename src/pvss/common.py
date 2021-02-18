
#from charm.toolbox.ecgroup import ECGroup as ec_group


#from petlib.bn import Bn
#from petlib.ec import EcGroup, EcPt


from petlib.ec import EcGroup
from petlib.bn import Bn

def gen_params(size):
    # Gp = ec_group() # FIXME: Is this correct?
    #Gp = ECGroup(prime192v2)
   #Gp.paramgen(size)
    
    
    
    g = group1.randomGen()
    G = Gp.p
    q = Gp.q

    return (Gp, G, q)
    