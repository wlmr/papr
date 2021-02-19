#!/usr/bin/env python3
#from charm.toolbox.integergroup import IntegerGroup

# Distribution

from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn


class PVSS():

    def __init__(self, params):
        global Gq
        global g
        global p
        global G
        global h
        (Gq, p, g, G, h) = params

    def gen_polynomial(self, t, n, secret, pub_keys):
        #assert k-1 <= t-1

        #size = k-1
        #assert size > 1
        assert n > t
        assert len(pub_keys) >= n-1

     #   import pdb; pdb.set_trace()
        #enc_secret = G.encode(secret)
        enc_secret = secret  # Should we encode it to be on curve?

        # Random number on the curve? Is that what we want?
        px = [p.random() for i in range(t)]
        px.append(enc_secret)

  

        commitments = self.get_commitments(g, px)
        shares_list = [self.calc_poly(px, t, i) for i in range(n)]

        enc_shares = self.get_encrypted_shares(pub_keys, shares_list) #  shares_list[:-1] ???

        X_i_list = [self.get_X_i(commitments, i) for i in range(1, n+1)]

        return (commitments, enc_shares, X_i_list, shares_list)

    def calc_poly(self, px, t, x):
        order_list = self.rev_range(t)
        result = 0

        q = p
        
        for (alpha, j) in zip(px, order_list):
            result = (result + alpha * (x**j)) % q
            #result = result * j * x * alpha
        
        #result = 0
        #for (alpha, i) in zip(px, rev_range(px)):
        #    result = (result + alpha * (x**i)) % q

        return result

    def rev_range(self, length):
        '''
        A counting list from length(list)-1 to 0
        '''
        
        # A reverse list. If length is 4 then the result is [3, 2, 1, 0]
        return range(length-1, -1, -1)

    def get_commitments(self, g, px):
        #import pdb; pdb.set_trace()
        return [p_i * g for p_i in px] # Reverse order, why does it not work in default order?
        # return [g**p_i for p_i in px]
        # return [C_3 C_2 C_1 C_0]

    def get_encrypted_shares(self, pub_keys, shares):
        #assert len(pub_keys) < (len(shares)-1)

        
        assert len(pub_keys) == len(shares) 
        Y_i_list = [shares[i]*y_i for (y_i, i) in zip(pub_keys, range(len(pub_keys)))]  # FIXME: Should we have mod p

        # Y_i_list = [y_i**shares[i]
        #           for (y_i, i) in zip(pub_keys, range(len(pub_keys)))]
        return Y_i_list

    def get_X_i(self, C_list, i):
        elements = [j*i*C_j for (C_j, j) in zip(C_list, reversed(range(len(C_list))))]
        #elements = [
        #    C_j**i**j for (C_j, j) in zip(C_list, reversed(range(len(C_list))))]
        
        ans = elements[0]
        for e in elements[1:]:
            ans + e
        

       # result = sum(elements) ##FIXME: Product, is this correct in eliptic curve??

        return ans # result #prod(elements)  # X_i


    def verify_correct_decryption(self, S_i, Y_i):
        pass

    def decode(self, S_list):
        ans = 1
        for (S_i, i) in zip(S_list, range(len(S_list))):  # Invert ??
            ans = ans * S_i**lagrange(i)

        return ans  # G**s

    def lagrange(self, i):
        pass
