#!/usr/bin/env python3
from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
#from dealer import PVSS
from hashlib import sha256


#class DLEQ():#

    # def __init__(self, params):
    #     global G
    #     global g
    #     global p
    #     global G
    #     (Gq, p, g, G) = params
        


def get_X_i_list(commitments, n):
    return [get_X_i(commitments, i) for i in range(1, n+1)]

def get_X_i(C_list, i):
    elements = [(i**j) * C_j for (C_j, j)
                in zip(C_list, range(len(C_list)))]

    ans = elements[0]
    for e in elements[1:]:
        ans = ans + e

    return ans


def DLEQ_prove(params, g_1, g_2, h_1, h_2, x_i):
    (_,p,_,_) = params
    w = p.random()
    (a_1, a_2) = DLEQ_prover_calc_a(g_1, g_2, w)
    c = hash(params,g_1, g_2, a_1, a_2)
    r = DLEQ_calc_r(params, w, x_i, c)
    return (c, r, a_1, a_2)

def DLEQ_prover_calc_a(g_1, g_2, w):
    a_1 = w * g_1
    a_2 = w * g_2
    return (a_1, a_2)

def DLEQ_prove_list(params, pub, y_list, shares_list):
    (_, p, g, _) = params
    X_list = pub['X_list']
    Y_list = pub['Y_list']

    assert len(X_list) == len(y_list)
    assert len(Y_list) == len(y_list)
    n = len(X_list)

    w_list = [p.random() for i in range(n)]
    a_1_list = [w_list[i] * g for i in range(n)]
    a_2_list = [w_list[i] * y_list[i] for i in range(n)]

    c = hash(params, X_list, Y_list, a_1_list, a_2_list)
    r_list = [DLEQ_calc_r(params, w, alpha, c)
                for (alpha, w) in zip(shares_list, w_list)]

    proof = {'c': c, 'r_list': r_list,
                'a_1_list': a_1_list, 'a_2_list': a_2_list}

    return proof

def hash(params, g_1, g_2, a_1, a_2) -> Bn:
    (_,p,_,_) = params
    state = str([g_1, g_2, a_1, a_2])
    H = sha256()
    H.update(state.encode("utf8"))
    hash_c = H.digest()
    c = Bn.from_binary(hash_c) % p
    return c

def DLEQ_calc_r(params, w, alpha, c):
    (_,p,_,_) = params
    r = (w - c * alpha) % p
    return r

def DLEQ_verifyer_calc_a(r, c, g_1, h_1, g_2, h_2):
    a_1 = r * g_1 + c * h_1
    a_2 = r * g_2 + c * h_2
    return (a_1, a_2)

def DLEQ_verify(params, y_list, pub, proof):
    (_,_,g,_) = params
    r_list = proof['r_list']
    c_claimed = proof['c']
    a_1_orig_list = proof['a_1_list']
    a_2_orig_list = proof['a_2_list']

    n = len(r_list)

    Y_list = pub['Y_list']

    X_list = get_X_i_list(pub['C_list'], n)

    c = hash(params, X_list, Y_list, a_1_orig_list, a_2_orig_list)

    # Prover lied about c
    if c_claimed != c:
        return False

    for (r_i, X_i, y_i, Y_i, a_1_orig, a_2_orig) in zip(r_list, X_list, y_list, Y_list, a_1_orig_list, a_2_orig_list):
        (a_1_new, a_2_new) = DLEQ_verifyer_calc_a(r_i, c, g, X_i, y_i, Y_i)

        if a_1_new != a_1_orig or a_2_new != a_2_orig:
            return False

    return True



