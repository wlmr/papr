
from charm.toolbox.integergroup import IntegerGroup as integer_group

def gen_params(size):
    Gp = integer_group()
    Gp.paramgen(size)
    g = group1.randomGen()
    G = Gp.p
    q = Gp.q

    return (Gp, G, q)
    