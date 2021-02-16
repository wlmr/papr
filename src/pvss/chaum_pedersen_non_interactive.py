#!/usr/bin/env python3

from charm.toolbox.hash_module import Hash




# y_i = g_2 
# X_i = h_1
# Y_i = h_2 



                    # g X_i y_i Y_i
def DLEQ_prover_1(Gq, g, X_list, y_list, Y_list, n):
    # g1 h1 g2 h2 

    # Should we have same of different w????

    w_list = [Gq.random() for i in range(1, n+1)]
    a_1_list = [g ** w_list[i] for i in range(len(w_list))]
    a_2_list = [y_list[i] ** w_list[i] for i in range(len(w_list))]



#    w = Gq.random()
 #   a_1 = g_1**w
 #   a_2 = g_2**w




   # Y_i = h_2
   # X_i = h_1

    c_list = [hash(X_list[i], Y_list[i], a_1_list[i], a_2_list[i]) for i in range(len(w_list))]
    # FIXME only one c ??
    # Multiple r 


    import pdb; pdb.set_trace()



    #for

    q = Gq.q
    r = (w - alpha * c)%q
    return r

    #return (a_1, a_2)

#def DLEQ_verifyer_1(Gq, a_1, a_2):
#    c = Gq.random()
#    return c

def DLEQ_prover_2(Gq, w, c, alpha)
    q = Gq.q
    r = (w - alpha * c)%q
    return r

def DLEQ_verifyer_2(Gq, r, c, g_1, h_1, g_2, h_2):
    a_1 = g_1**r * h_1 ** c
    a_2 = g_2**r * h_2 ** c
    return a_1 == a_2


def hash(X_i, Y_i, a_1_i, a_2_i):
    hash_func = Hash()
    hash_result = hash_func.hashToZr(X_i, Y_i, a_1_i, a_2_i)
    return hash_result

