#!/usr/bin/env python3

# from charm.toolbox.hash_module import Hash


from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from dealer import PVSS

from hashlib import sha256



# y_i = g_2 
# X_i = h_1
# Y_i = h_2 

class DLEQ():


    def __init__(self, params):    
        global G
        global g
        global p 
        global G
        global h
        (Gq, p, g, G, h) = params
        
    #    global q = q
        pass
                        # g X_i y_i Y_i
    def DLEQ_prover_1(self,g, X_list, y_list, Y_list, p_of_i):                   
    #(Gq, q, g, X_list, y_list, Y_list, n):
        assert len(X_list) == len(y_list)
        assert len(Y_list) == len(y_list)
        n = len(X_list)


        # NOTE p(0) == alpha_0 and so on
        
        # g1 h1 g2 h2 

        # Should we have same of different w????

#        w_list = [p.random() for i in range(n)]
#        a_1_list = [g ** w_list[i] for i in range(n))]
#        a_2_list = [y_list[i] ** w_list[i] for i in range(n)]




        w_list = [p.random() for i in range(n)]
        a_1_list = [w_list[i] * g           for i in range(n)]
        a_2_list = [w_list[i] * y_list[i]   for i in range(n)]




    #    w = Gq.random()
    #   a_1 = g_1**w
    #   a_2 = g_2**w




    # Y_i = h_2
    # X_i = h_1

        # c_list = [hash(X_list[i], Y_list[i], a_1_list[i], a_2_list[i]) for i in range(len(w_list))]
        
        
        #c =  hash([X_list[:], Y_list[:], a_1_list[:], a_2_list[:]]) 
        
        # FIXME only one c ??
        # Multiple r 
        import pdb; pdb.set_trace()


        state = str([X_list[:], Y_list[:], a_1_list[:], a_2_list[:]])
        H = sha256()
        H.update(state.encode("utf8"))
        hash_c = H.digest()
     

        #c = c % p #???


        # c = Gq.hash_to_point(state.encode("utf8"))
        #c = sha256(str([X_list[:], Y_list[:], a_1_list[:], a_2_list[:]]))
        #import pdb; pdb.set_trace()



        #hash_c = challenge(state)
        c = Bn.from_binary(hash_c) % p
        
        #return (c, r)




        #for

        # q = Gq.q
       # r = (w - alpha * c)#%q
        #return r

        #q = p


        # SHOUDL BE MOD ps
        #r_list = [w-alpha*c for (alpha, w) in zip(p_of_i,  w_list)]
        # FIXME: How do we know alpha? 

        r_list = [self.calc_r(w,alpha,c) for (alpha, w) in zip(p_of_i, w_list)]

        return (c, r_list)
        #return (a_1, a_2)

    #def DLEQ_verifyer_1(Gq, a_1, a_2):
    #    c = Gq.random()
    #    return c

    def calc_r(self, w, alpha, c):
        r = (w - c * alpha) % p
        return r


  #  def DLEQ_prover_2(Gq, w, c, alpha):
        # q = Gq.q
  #      r = (w - alpha * c) #%q
  #      return r


    def DLEQ_verify(self, params, y_list, X_list, Y_list, r_list, c):
        
        for (r_i, X_i, y_i, Y_i) in zip(r_list, X_list, y_list, Y_list):
            res = self.DLEQ_verifyer_2(params, r_i, c, g, X_i, y_i, Y_i)
            if res != True:
                return False    
        return True

    def DLEQ_verifyer_2(self, params, r, c, g_1, h_1, g_2, h_2):
        a_1 = r* g_1 + c* h_1 
        a_2 = r*g_2 + c* h_2
        return a_1 == a_2


    #def hash(X_i, Y_i, a_1_i, a_2_i):
    #    hash_func = Hash()
    #    hash_result = hash_func.hashToZr(X_i, Y_i, a_1_i, a_2_i)
    #    return hash_result


   # def random(q):
    #    pass
        #new Gq
 #       return 
#

if __name__ == "__main__":
    Gq = EcGroup()
    # import pdb; pdb.set_trace()
    p = Gq.order()
    g = Gq.generator()
    G = Gq.hash_to_point(b'G')             ## IS THIS A GENERATOR??? #
    h = Gq.hash_to_point("mac_ggm".encode("utf8"))

    m = Bn.from_binary(b'This is a test')
    params = (Gq, p, g, G, h)
    cpni = DLEQ(params)
    pvss = PVSS(params)

    # import pdb; pdb.set_trace()

    n = 4
    t = 3

    demo_priv_keys = [p.random() for i in range(n)]
    demo_pub_keys = [priv_key * G for priv_key in demo_priv_keys] # ? 


    (C_list, Y_list, X_list, shares_list) = pvss.gen_polynomial(t, n, m, demo_pub_keys)

    (c, r_list) = cpni.DLEQ_prover_1(g, X_list, demo_pub_keys , Y_list, shares_list)
    
    assert cpni.DLEQ_verify(params, demo_pub_keys ,X_list,Y_list,r_list,c) == True


    #X_list = [0, 1, 2, 3]
    #y_list = [0, 1, 2, 3]
    #Y_list = [0, 1, 2, 3]
    #cpni.DLEQ_prover_1(X_list, y_list, Y_list)

    
    #(pk, sk) = el.keygen()
    #(c,r) = el.encrypt(pk, m)
    #print(el.decrypt(pk,sk,c))