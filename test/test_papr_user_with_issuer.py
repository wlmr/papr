from papr.papr_user_with_issuer import User
from papr.papr_issuer import Issuer
from papr.ecdsa import sign, verify
import pvss.pvss as pvss
# from petlib.pack import encode, decode
from amac.credential_scheme import setup as setup_cmz


class TestPaprUserWithIssuer:

    def test_enroll(self):
        issuer = Issuer()
        issuer.setup(3, 5)
        identities = ["Patrik Kron", "Wilmer Nilsson", "Clark Kent", "Ted Kaczynski", "Bruce Wayne"]
        users = [User(issuer) for _ in identities]
        t_id_list = [u.req_enroll(id) for id, u in zip(identities, users)]
        assert t_id_list is not None
    

        