from charm.toolbox.integergroup import IntegerGroup


def setup(k):
    """ generate all public parameters """
    G = IntegerGroup()
    G.paramgen(k)
    g = G.randomGen()
    h = G.randomGen()
    return (G, G.p, g, h)


def keygen(params, n):
    """ mac DDH keygen """
    assert n > 0
    (G, p, g, h) = params
    #sk = [G.random() for _ in range(2*n+3)] # case n = 1 gives us x0, x1, y0, y1, z (3+2*n).  
    sk_names = ['x0','x1','y0','y1','z']
    sk = {name:G.random() for name in sk_names}
    iparams = {name.upper():h**sk[name] for name in sk_names[:-1]}
    return (sk, iparams)


def mac(params, sk, m):
    """ compute mac GGM """
    assert len(sk) > 0 and m
    (G, p, g, h) = params
    r = G.random() 
    em = G.encode(m)
    #import pdb; pdb.set_trace()
    Hx = sk['x0'] + sk['x1'] * em   #x0 + x1*m                  # Hx becomes larger than mod value??!??!
    Hy = sk['y0'] + sk['y1'] * em   #y0 + y1*m
    #Hx = sk[0] + sum([sk[i+1] * em[i] for i in range(n)])
    #Hy = sk[0+n] + sum([sk[n+i+1] * em[i] for i in range(n)])
    
    sigma_w = g**r 
    sigma_x = g**(r*Hx)
    sigma_y = g**(r*Hy)
    sigma_z = g**(r*sk['z']) # g**(r*z)
    
    sigma = (sigma_w, sigma_x, sigma_y, sigma_z) 
    return sigma


def verify(params, sk, m, sigma):
    """ verify mac DDH """
    assert len(sk) > 0 and m
    (G, p, g, h) = params
    (sigma_w, sigma_x, sigma_y, sigma_z) = sigma
    em = G.encode(m)
    Hx = sk['x0'] + sk['x1']*em   #x0 + x1*m
    Hy = sk['y0'] + sk['y1']*em   #y0 + y1*m
    #Hx = sk[0]   + sum([sk[i+1]*m[i] for i in range(n)])
    #Hy = sk[0+n] + sum([sk[n+i+1]*m[i] for i in range(n)])

    return sigma_w != 1 and sigma_x == sigma_w**Hx and sigma_y == sigma_w**Hy and sigma_z == sigma_w**sk['z']


#Debug
def test():
    params = setup(500)
    m = b'my secret identity'
    n = len(m)
    (sk,iparams) = keygen(params, 1)
    sigma = mac(params, sk, m)
    assert verify(params, sk, m, sigma)

test()