#!/usr/bin/env python3

import dealer as d
import common as common

def test_commit(): 
    px = [12, 37, 94, 56]
    g = 13
    expected = [13**12, 13**37, 13**94]
    assert d.get_commitments(g, px) == expected


def test_enc():
    pubkeys = [12, 13, 45, 34]
    px = [12, 37, 94, 56]
    
    expected = [12**12, 13**37, 94**45, 56**34]

   
    assert d.get_encrypted_shares(pubkeys, px) == expected



def test_calc_poly():
    px = [12, 37, 94, 56]

    x = 5 
    q = 1024

    import pdb; pdb.set_trace()
    assert d.calc_poly(px, x, q) == 903
    # 12*5^3 + 37 * 5^2 + 94 * 5 + 56  MOD 1024 = 903 



def test_a():
    size = 170
    params = common.gen_params(size)
    d.gen_polynomial(params, 5, 3, 8, 712)





test_a()



#test_commit()
# test_enc()
#test_calc_poly()

