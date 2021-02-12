#!/usr/bin/env python3


def gen_key():
    pass
    # Return x_i private key

def get_pub_key(G, x_i):
    y_i = G**x_i
    return y_i


def decrypt(params, Y_i, x_i):
    S = Y_i**(1/x_i)
    #ALSO DLEQ??





