#!/usr/bin/env python3
#from charm.toolbox.integergroup import IntegerGroup

# Distribution

def gen_polynomial(params, t, size, secret):
    assert size <= t-1

    (Gp, G, g) = params

    import pdb; pdb.set_trace()
    enc_secret = secret #= G.encode(secret)
    
    coeff = [Gp.random() for i in range(size)]
    coeff = [coeff[:], enc_secret]
    return coeff
    # pass
    # return px = [a3 a2 a1 a0] in a3 x**3 + a2 x**2 + a1 x**1 + a0 

def get_commitments(g, px):
    return  [g**p_i for p_i in px[:-1]]
    # return [C_3 C_2 C_1]

def get_encrypted_shares(pub_keys, px):
    assert len(pub_keys) < (len(px)-1)
    Y_i_list = [y_i**px[i] for (y_i, i) in zip(pub_keys, range(len(pub_keys)))]
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
