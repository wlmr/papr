from amac.credential_scheme import setup as setup_cmz, cred_keygen as cred_keygen_cmz


class Issuer:

    def setup(self, k, n):
        """
        TODO: 1. generate t generators instead of just two,
              2. publish return value to Lsys.
        """
        params = setup_cmz()
        (G, p, g0, g1) = params
        (x_sign, x_encr) = (p.random(), p.random())
        (y_sign, y_encr) = (x_sign * g0, x_encr * g0)
        (iparams, i_sk) = cred_keygen_cmz(params)
        self.iparams = iparams
        self.i_sk = i_sk
        crs = ",".join([p, g0, g1, n, k, iparams['Cx0']])
        return (crs, (y_sign, y_encr))
