from papr.ecdsa import verify
import papr.utils as utils


class Ledger():

    def __init__(self, y_sign):
        self.ledger = []
        self.hashes = []
        self.issuer_y_sign = y_sign

    def peek(self):
        if len(self.ledger) > 0:
            return self.ledger[-1]
        else:
            return None

    def read(self, index: int = None):
        if index is None:
            return self.ledger
        elif index in range(0, len(self.ledger)):
            return self.ledger[index]
        else:
            return None

    def read_since(self, index: int):
        if index in range(0, len(self.ledger)):
            return (self.ledger[index:], self.hashes[index:])
        else:
            return ([], [])

    def has(self, field_value, tuple_index):
        return field_value in [entry[tuple_index] for entry in self.ledger]

    def add(self, params, entry, issue_signature):
        """
        Only allows adds comming from the issuer, as all
        calls must include a valid signature.
        """
        (G, p, g, _) = params
        r, s = issue_signature
        if verify(G, p, g, r, s, self.issuer_y_sign, [entry]):
            self.ledger.append(entry)
            self.update_hash(entry)
            return True
        return False

    def update_hash(self, entry):
        if len(self.hashes) != 0:
            last_hash = self.hashes[-1]
        else:
            last_hash = 0
        m = utils.hash([entry, last_hash])
        self.hashes.append(m)


class LedgerDict():

    def __init__(self, y_sign):
        self.ledger = {}
        self.issuer_y_sign = y_sign

    def peek(self):
        list(self.ledger)[-1]

    def read(self, key):
        if key not in self.ledger:
            return None
        return self.ledger[key]

    def has(self, key, tuple_index=None):
        if key not in self.ledger:
            return False
        if tuple_index is None:
            return True
        if hasattr(self.ledger[key], "__getitem__") and tuple_index in range(len(self.ledger[key])):
            return True

    def add(self, params, entry, issue_signature):
        """
        Only allows adds comming from the issuer, as all
        calls must include a valid signature.
        """
        (G, p, g, _) = params
        r, s = issue_signature
        (k, v) = entry
        if verify(G, p, g, r, s, self.issuer_y_sign, [entry]):
            self.ledger[k] = v
            return True
        return False
