from papr_money.bank import Bank
from papr_money.customer_with_issuer import Customer
from papr.ecdsa import sign, verify


class TestCustomerWithIssuer:
    def test_enroll(self):
        bank = Bank()
        real_id = "first"
        params, (y_sign, y_encr), iparams, _, user_list, _, _ = bank.setup(3, 10)
        user = Customer(real_id, bank)
        ret = user.req_enroll()

        assert ret is not None
        _, (r, s), pub_id = ret
        print(f"user_list.peek():   {user_list.peek()}\n")
        assert user_list.peek() is not None

        assert user_list.has(real_id, 0)
        (G, p, g0, _) = params
        assert verify(G, p, g0, r, s, y_sign, [(real_id, pub_id)])
