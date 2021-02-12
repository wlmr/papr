#!/usr/bin/env python3

import dealer as d

def test_commit(): 
    px = [12, 37, 94, 56]
    g = 13
    expected = [13**12, 13**37, 13**94]
    assert d.get_commitments(g, px) == expected


def test_enc():
    pubkeys = [12, 13, 45, 34]
    px = [12, 37, 94, 56]
    
    expected = [12**12, 13**37, 94**45, 56**34]

    import pdb; pdb.set_trace()
    assert d.get_encrypted_shares(pubkeys, px) == expected





test_commit()
test_enc()