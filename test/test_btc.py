from bit.wallet import PrivateKeyTestnet
from petlib.bn import Bn
from papr.user import User
from papr.issuer import Issuer
from amac.credential_scheme import setup as setup_cmz
from bit.format import bytes_to_wif
from petlib.ec import EcPt
import papr.utils as utils
import pytest

from bit.network import NetworkAPI


class TestBTC:
    @pytest.mark.skip(reason="Disabled")
    def test_correct_curve(self):
        btc_key = PrivateKeyTestnet()
        (G, _, g0, _) = setup_cmz(3)
        priv_cred = Bn.from_decimal(str(btc_key.to_int()))
        pub_cred = priv_cred * g0
        wif = bytes_to_wif(btc_key.to_bytes(), compressed=False)
        key2 = PrivateKeyTestnet(wif)

        assert pub_cred == EcPt.from_binary(key2.public_key, G)

    def test_curve_in_user(self):
        issuer = Issuer()
        (k, n) = (3, 10)
        params, (y_sign, y_encr), iparams, _, _, _, _ = issuer.setup(k, n)
        (G, _, _, _) = params

        btc_key = PrivateKeyTestnet()

        # Convert private key to Bn format
        btc_priv_key = Bn.from_decimal(str(btc_key.to_int()))
        user = User(params, iparams, y_sign, y_encr, k, n, btc_priv_key)
        (_, this_should_be_btc_public_key) = user.cred_sign_1()

        # Convert to uncompressed format:
        wif = bytes_to_wif(btc_key.to_bytes(), compressed=False)
        key2 = PrivateKeyTestnet(wif)
        public_key_in_ecpt_format = EcPt.from_binary(key2.public_key, G)

        assert public_key_in_ecpt_format == this_should_be_btc_public_key

    def test_if_pubkey_is_same(self):
        issuer = Issuer()
        (k, n) = (3, 10)
        params, (y_sign, y_encr), iparams, _, _, _, _ = issuer.setup(k, n)
        (G, _, _, _) = params
        btc_key = PrivateKeyTestnet()

        # Convert private key to Bn format
        btc_priv_key = Bn.from_decimal(str(btc_key.to_int()))
        user = User(params, iparams, y_sign, y_encr, k, n, btc_priv_key)
        (_, this_should_be_btc_public_key) = user.cred_sign_1()

        # Convert to uncompressed format:
        wif = bytes_to_wif(btc_key.to_bytes(), compressed=False)
        key2 = PrivateKeyTestnet(wif)
        public_key_in_ecpt_format = EcPt.from_binary(key2.public_key, G)

        assert EcPt.from_binary(key2.public_key, G) == EcPt.from_binary(btc_key.public_key, G)
        assert public_key_in_ecpt_format == this_should_be_btc_public_key

    def test_pubkey_to_addr(self):
        issuer = Issuer()
        (k, n) = (3, 10)
        params, (y_sign, y_encr), iparams, _, _, _, _ = issuer.setup(k, n)
        (G, _, _, _) = params
        btc_key = PrivateKeyTestnet()

        # Convert private key to Bn format
        btc_priv_key = Bn.from_decimal(str(btc_key.to_int()))
        user = User(params, iparams, y_sign, y_encr, k, n, btc_priv_key)
        (_, this_should_be_btc_public_key) = user.cred_sign_1()
        adr = btc_key.address
        new_adr = utils.pub_key_to_addr(this_should_be_btc_public_key.export())

        assert adr == new_adr
        assert utils.pub_key_to_addr(this_should_be_btc_public_key) == adr

        wif = bytes_to_wif(btc_key.to_bytes(), compressed=True)
        key2 = PrivateKeyTestnet(wif)
        public_key_in_ecpt_format = EcPt.from_binary(key2.public_key, G)

        assert public_key_in_ecpt_format == this_should_be_btc_public_key
