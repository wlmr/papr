#!/usr/bin/env python3
from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from dealer import PVSS
from hashlib import sha256

class DLEQ():


    def __init__(self, params):    
        global G
        global g
        global p 
        global G
        global h
        (Gq, p, g, G, h) = params
        pass
                        # g X_i y_i Y_i
    def DLEQ_prover_1(self,g, X_list, y_list, Y_list, p_of_i):                   
    #(Gq, q, g, X_list, y_list, Y_list, n):

        import pdb; pdb.set_trace()
        assert len(X_list) == len(y_list)
        assert len(Y_list) == len(y_list)
        n = len(X_list)


        # NOTE p(0) == alpha_0 and so on

        # Should we have same of different w????

        w_list = [p.random() for i in range(n)]
        a_1_list = [w_list[i] * g           for i in range(n)]
        a_2_list = [w_list[i] * y_list[i]   for i in range(n)]

        print("Debug a_1_list:" + str(a_1_list))
        print("Debug a_2_list:" + str(a_2_list))
       
        c = self.hash(X_list, Y_list, a_1_list, a_2_list)
        r_list = [self.calc_r(w,alpha,c) for (alpha, w) in zip(p_of_i, w_list)]

        return (c, r_list)
       

    def hash(self, X_list, Y_list, a_1_list, a_2_list):
        state = str([X_list[:], Y_list[:], a_1_list[:], a_2_list[:]])
        H = sha256()
        H.update(state.encode("utf8"))
        hash_c = H.digest()
        c = Bn.from_binary(hash_c) % p
        return c
        

    def calc_r(self, w, alpha, c):
        r = (w - c * alpha) % p
        return r



    def DLEQ_verify(self, params, y_list, X_list, Y_list, r_list, c):
        a_res = []
        for (r_i, X_i, y_i, Y_i) in zip(r_list, X_list, y_list, Y_list):
            a_res.append(self.DLEQ_verifyer_2(params, r_i, c, g, X_i, y_i, Y_i))
            #if res != True:
            #    return False
        print(str(a_res))    
        import pdb; pdb.set_trace()
        #return True

    def DLEQ_verifyer_2(self, params, r, c, g_1, h_1, g_2, h_2):
        a_1 = r * g_1 + c * h_1 
        a_2 = r * g_2 + c * h_2
        # import pdb; pdb.set_trace()
        return (a_1, a_2)#a_1 == a_2
        # FIXME: START HERE. a_2 gives wanted result, a_1's differ!

if __name__ == "__main__":
    Gq = EcGroup()
    p = Gq.order()
    g = Gq.generator()
    G = Gq.hash_to_point(b'G')
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

    verifyer_X_list = pvss.get_X_i_list(C_list, n)

    assert cpni.DLEQ_verify(params, demo_pub_keys ,X_list,Y_list,r_list,c) == True
