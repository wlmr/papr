from papr.ecdsa import verify


class Papr_list():

    def __init__(self, y_sign):
        self.papr_list = []
        self.issuer_y_sign = y_sign

    def peek(self):
        return self.papr_list[-1]

    def read(self, index: int):
        if not index:
            return self.papr_list
        elif index in range(0, len(self.papr_list)):
            return self.papr_list[index]
        else:
            return (None, None)

    def has(self, id, index):
        return id in [entry[index] for entry in self.papr_list]

    def add(self, params, entry, issue_signature):
        """
        Only allows adds comming from the issuer, as all
        calls must include a valid signature.
        """
        (G, p, g, _) = params
        r, s = issue_signature
        if verify(G, p, g, r, s, self.issuer_y_sign, [*entry]):
            self.papr_list.append(entry)
            return True
        return False
