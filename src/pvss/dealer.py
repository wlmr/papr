#!/usr/bin/env python3
#from charm.toolbox.integergroup import IntegerGroup

# Distribution

def gen_polynomial(params, t, k, n , secret):
    assert k-1 <= t-1

    size = k-1
    assert size > 1

    (Gp, G, g) = params
    q = Gp.q

    import pdb; pdb.set_trace()
    enc_secret = G.encode(secret)
    
    coeff = [Gp.random() for i in range(size)]
    coeff = [coeff[:], enc_secret]

    shares_list = [calc_poly(coeff, i, q) for i in range(n)] 
    
    return (coeff, shares_list)
    # pass
    # return px = [a3 a2 a1 a0] in a3 x**3 + a2 x**2 + a1 x**1 + a0 

def calc_poly(px, x, q):
    result = 0
    for (alpha, i) in zip(px, rev_range(px)):
        result = (result + alpha* (x**i))%q

    return result
    

def rev_range(list):
    length = len(list)
    return range(length-1, -1 , -1) # A reverse list. If length is 4 then the result is [3, 2, 1, 0]

def get_commitments(g, px):
    return  [g**p_i for p_i in px[:-1]]
    # return [C_3 C_2 C_1]

def get_encrypted_shares(pub_keys, shares):
    #assert len(pub_keys) < (len(shares)-1)
    assert len(pub_keys) == len(shares)
    Y_i_list = [y_i**shares[i] for (y_i, i) in zip(pub_keys, range(len(pub_keys)))]
    return Y_i_list


def get_X_i(C_list, i):
    elements = [C_j**i**j for (C_j, j) in zip(C_list, reversed(range(len(C_list))))]
    return prod(elements) # X_i



# Decrypt

#Pooling

def verify_correct_decryption(S_i, Y_i):
    pass

def decode(S_list):
    ans = 1
    for (S_i, i) in zip(S_list, range(len(S_list))): # Invert ??
        ans = ans* S_i**lagrange(i)
    
    return ans #G**s

def lagrange(i):
    pass
