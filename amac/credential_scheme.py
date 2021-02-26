from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from typing import Optional
from amac.proofs import make_pi_prepare_obtain, verify_pi_prepare_obtain
from amac.proofs import make_pi_issue, verify_pi_issue
from amac.proofs import make_pi_show, verify_pi_show
from amac.mac_ggm import setup as setup_ggm, keygen as keygen_ggm
from amac.elgamal import keygen as keygen_elgamal, encrypt as encrypt_elgamal, decrypt as decrypt_elgamal


BnDict = dict[str, Bn]
EcPtDict = dict[str, EcPt]
Params = tuple[EcGroup, Bn, EcPt, EcPt]
ZKP = tuple[Bn, BnDict]
Credential = tuple[EcPt, Bn]
Sigma = tuple[EcPt, EcPt, EcPt]


def setup(k: int) -> Params:
    """
    TODO: should take a number k that determines the number of bits of the
    field underlying the EC.
    Returns params := (G,p,g,h)
    """
    return setup_ggm(k)


def cred_keygen(params: Params) -> tuple[EcPtDict, BnDict]:
    """
    Run by issuer to generate issuer secret key and public issuer parameters iparams.
    """
    (_, p, g, h) = params
    (issuer_sk, iparams) = keygen_ggm(params)
    issuer_sk['x0_tilde'] = p.random()
    iparams['Cx0'] = issuer_sk['x0'] * g + issuer_sk['x0_tilde'] * h
    return iparams, issuer_sk


def prepare_blind_obtain(params: Params, m: bytes) -> tuple[BnDict, EcPtDict, EcPtDict, ZKP]:
    """
    User asks for credential.
    1. Generate elgamal keypair,
    2. encrypt each attribute multiplied by g,
    with the elgamal key with some random r, as according to elgamal,
    3. sends the encryption E along with proof of knowledge of r and m to issuer.
    """
    (_, p, g, _) = params
    (user_pk, user_sk) = keygen_elgamal((g, p))
    gamma = user_pk['h']
    M = p.from_binary(m)
    (ciphertext, r) = encrypt_elgamal(user_pk, M)
    pi_prepare_obtain = make_pi_prepare_obtain(params, gamma, ciphertext, r, M)
    return user_sk, user_pk, ciphertext, pi_prepare_obtain


def blind_issue(params: Params, iparams: EcPtDict, i_sk: BnDict,
                gamma: EcPt, ciphertext: EcPtDict,
                pi_prepare_obtain: ZKP) -> Optional[tuple[EcPt, EcPtDict, ZKP, EcPtDict]]:
    """
    Carried out by issuer.
    1. Chooses a random b and computes u = g^b,
    2. rearanges e to e'_u' as described in the paper,
    3. sends (u, e'_u') and proof of knowledge of x's x_tilde, b and r back to
     the user.
    """
    if verify_pi_prepare_obtain(params, gamma, ciphertext, pi_prepare_obtain):
        (_, p, g, _) = params
        b = p.random()
        u = b * g
        bsk = {'b'+k: (b * v) % p for (k, v) in i_sk.items()}
        biparams = {'b'+k:  b * v for (k, v) in iparams.items()}
        r = p.random()
        e1 = r * g + b * i_sk['x1'] * ciphertext['c1']
        e2 = r * gamma + b * (i_sk['x0'] * g + i_sk['x1'] * ciphertext['c2'])
        e_u_prime = {'c1': e1, 'c2': e2}
        pi_issue = make_pi_issue(params, i_sk, iparams, gamma, ciphertext, b, bsk, r)
        return u, e_u_prime, pi_issue, biparams
    else:
        return None


def blind_obtain(params: Params, iparams: EcPtDict, u_sk: BnDict, u: EcPt,
                 e_u_prime: EcPtDict, pi_issue: ZKP, biparams: EcPtDict,
                 gamma: EcPt, ciphertext: EcPtDict) -> Optional[tuple[EcPt, Bn]]:
    """
    Carried out by user.
    1. verifies pi_issue,
    2. user decrypts e_prime to get u_prime. Credential is (u,u_prime).
    """
    if verify_pi_issue(params, iparams, u, e_u_prime, pi_issue,
                       biparams, gamma, ciphertext):
        return u, decrypt_elgamal(u_sk, e_u_prime)
    else:
        return None


def blind_show(params: Params, iparams: EcPtDict,
               cred: Credential, M: bytes) -> tuple[Sigma, ZKP]:
    """
    Carried out by user who wants to prove possession of a credential by:
    1. generate three random values: r, z, a,
    2. randomize credential with a,
    3. computes commitments Cm and Cu_prime and sends the "signature" sigma
    and a proof of the signature's correctness.
    """
    (_, p, g, h) = params
    m = p.from_binary(M)
    (r, z, a) = (p.random(), p.random(), p.random())
    (u0, u0_prime) = cred
    (u, u_prime) = (a * u0, a * u0_prime)
    Cm = m * u + z * h
    Cu_prime = u_prime + r * g
    sigma = (u, Cm, Cu_prime)
    pi_show = make_pi_show(params, iparams, m, r, z, sigma)
    return sigma, pi_show


def show_verify(params: Params, iparams: EcPtDict, i_sk: BnDict, sigma: Sigma, pi_show: ZKP) -> bool:
    """
    Verifies a request for a blind_show.
    """
    (u, Cm, Cu_prime) = sigma
    V = (i_sk['x0'] * u + i_sk['x1'] * Cm) - Cu_prime
    return verify_pi_show(params, iparams, sigma, pi_show, V)
