# Algebraic MACs for keyed-verification anonymous credentials
This folder implements the system described in the (paper)[https://eprint.iacr.org/2013/516.pdf]

## The dictionaries 
Currently, quite a few dictionaries are tossed around in the implementation.
Below follows a brief "dictionary dictionary", to make the code easier to follow.

### params: (G,p,g,h) -- public variables that describes the group 
### issuer_sk -- issuer's secret keys
{
    'x0' : random, 
    'x1' : random,
    'x0_tilde': random
} 
### iparams  -- public variables 
{
    'X1' : x1 * g, 
    'Cx0': x0 * g + x0_tilde * h
}
### user_sk -- user's secret elgamal keys
{
    'x': x
}
### user_pk -- user's public elgamal keys
{
    'g': g,
    'h': x * g,
    'p': p}
}
### ciphertext -- user's elgamal-encrypted attribute g^m
{
    'c1': y * user_pk['g']
    'c2': m * user_pk['g'] + y * user_pk['h']
}
where y = p.random()

### bsk
{'b'+k: (b * v) % p for (k, v) in i_sk.items()}

### biparam -- iparams raised to a random value b. (Commit to b)
{'b'+k:  b * v for (k, v) in iparams.items()}

### e_u_prime -- credential
{
    'c1': e1,
    'c2': e2
}
where:
    e1 = r * g + b * i_sk['x1'] * ciphertext['c1']
    e2 = r * gamma + b * (i_sk['x0'] * g + i_sk['x1'] * ciphertext['c2'])