#!/usr/bin/env python3

# We want non interactive version, i think.  

def DLEQ_prover_1(Gq, g_1, h_1, g_2, h_2): 
    w = Gq.random()
    a_1 = g_1**w
    a_2 = g_2**w
    return (a_1, a_2)

def DLEQ_verifyer_1(Gq, a_1, a_2):
    c = Gq.random()
    return c

def DLEQ_prover_2(Gq, w, c, alpha)
    q = Gq.q
    r = (w - alpha * c)%q
    return r

def DLEQ_verifyer_2(Gq, r, c, g_1, h_1, g_2, h_2):
    a_1 = g_1**r * h_1 ** c
    a_2 = g_2**r * h_2 ** c
    return a_1 == a_2
