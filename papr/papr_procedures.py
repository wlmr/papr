from amac.credential_scheme import setup as setup_cmz, cred_keygen as cred_keygen_cmz
from amac.credential_scheme import prepare_blind_obtain as prepare_blind_obtain_cmz
from amac.credential_scheme import blind_issue as blind_issue_cmz
from amac.credential_scheme import blind_obtain as blind_obtain_cmz
from amac.credential_scheme import blind_show as blind_show_cmz
from amac.credential_scheme import show_verify as show_verify


def setup(self, k, n):
    """
    TODO: [ ] publish return value to Lsys.
    """
    params = setup_cmz()
    (G, p, g0, g1) = params
    (x_sign, x_encr) = (p.random(), p.random())
    (y_sign, y_encr) = (x_sign * g0, x_encr * g0)
    (iparams, i_sk) = cred_keygen_cmz(params)
    crs = ",".join([p, g0, g1, n, k, iparams['Cx0']])
    return params, (x_sign, x_encr), (y_sign, y_encr), (iparams, i_sk), crs


def req_enroll_1(params, id):
    (G, p, g0, g1) = params
    priv_id = p.random()
    pub_id = priv_id * g0
    return id, priv_id, pub_id


def req_enroll_2():
    pass


def iss_enroll_1(params, iparams, i_sk, gam):
    pass


def iss_enroll_1(params, iparams, i_sk, gamma, ciphertext, pi_prepare_obtain):
    """
    def blind_issue(params: Params, iparams: EcPtDict, i_sk: BnDict,
            gamma: EcPt, ciphertext: EcPtDict,
            pi_prepare_obtain: ZKP) -> Optional[tuple[EcPt, EcPtDict, ZKP, EcPtDict]]:
    """
    pass
