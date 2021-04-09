from papr.ecdsa import verify


class Ledger():

    def __init__(self, y_sign):
        self.ledger = []
        self.issuer_y_sign = y_sign

    def peek(self):
        return self.ledger[-1]

    def read(self, index: int):
        if not index:
            return self.ledger
        elif index in range(0, len(self.ledger)):
            return self.ledger[index]
        else:
            return None

    def has(self, id, index):
        return id in [entry[index] for entry in self.ledger]

    def add(self, params, entry, issue_signature):
        """
        Only allows adds comming from the issuer, as all
        calls must include a valid signature.
        """
        (G, p, g, _) = params
        r, s = issue_signature
        if verify(G, p, g, r, s, self.issuer_y_sign, [*entry]):
            self.ledger.append(entry)
            return True
        return False
