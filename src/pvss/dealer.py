#!/usr/bin/env python3




#Distribution

def gen_polynomial(t, size):
    assert size <= t-1
    pass
    #return px = [a3 a2 a1 a0] in a3 x**3 + a2 x**2 + a1 x**1 + a0 

def get_commitments(g, px)
    return g**px[:-1]
    # return [C_3 C_2 C_1]

def get_encrypted_shares(pub_keys, px):
    Y_i_list = [yi**px[i] for (y_i, i) in zip(pub_keys, reversed(range(1,len(pub_keys)+1))]
    return Y_i_list


def get_X_i(C_list, i):
    elements = [C_j**i**j for (C_j, j) in zip(C_list, reversed(range(len(C_list))))]
    return prod(elements) # X_i

