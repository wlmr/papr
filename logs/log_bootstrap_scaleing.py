from papr.user import User
from papr.issuer import Issuer
from papr.ecdsa import sign, verify
import pvss.pvss as pvss
from amac.credential_scheme import setup as setup_cmz
import pytest
import time
from test.procedures import bootstrap_procedure, enroll_procedure



k_max = 51 #51
n_max = 100 #100
for k in range(3, k_max):
    for n in range(k, n_max):
        issuer = Issuer()

        begin = time.time()
    
        # Bootstrap 
        params, (y_sign, y_encr), iparams, sys_list, user_list, cred_list, rev_list, users, pub_creds, pub_ids = bootstrap_procedure(k, n, issuer)
        end = time.time()

        begin_extra_users = time.time()
        for i in range(10):
            user = User(params, iparams, y_sign, y_encr, k, n)
            enroll_procedure("extra"+str(i), issuer, user)
        end_extra_users = time.time()


        print("(" + str(k) + ", " + str(n) + "): " + str(end-begin) + " s. Extra users: " + str(end_extra_users-begin_extra_users) + " s")

