from papr.ecdsa import verify


class User_list():

    def __init__(self, y_sign):
        self.user_list = []
        self.issuer_y_sign = y_sign

    def peek(self):
        return self.user_list[len(self.user_list)-1]

    def read(self, index: int):
        if not index:
            return self.user_list
        elif index in range(0, len(self.user_list)):
            return self.user_list[index]
        else:
            return (None, None)

    def has(self, id):
        return id in [id for (_, id, _) in self.user_list]

    def add(self, params, pub_id, id, issue_signature):
        """
        Only allows adds comming from the issuer, as all add calls must include a valid signature.
        """
        r, s = issue_signature
        if verify(params, r, s, self.issuer_y_sign, pub_id.get_affine()[0]):
            self.user_list.append((pub_id, id, issue_signature))
            return True
        return False
