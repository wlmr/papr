""" aMAC zero-knowledge proofs. """
from petlib.bn import Bn
from hashlib import sha256
from binascii import hexlify


def to_challenge(elements):
    """ generates a Bn challenge by hashing a number of EC points """
    Cstring = b",".join([hexlify(x.export()) for x in elements])
    Chash = sha256(Cstring).digest()
    return Bn.from_binary(Chash)


def make_pi_prepare_obtain(params, gamma, ciphertext, r, m):
	""" make prepare issuance proof """
	(_, p, g, h) = params
	wr,wm = (p.random(),p.random())
	Aw = wr * g
	Bw = wr * gamma + wm * g
	c = to_challenge([g, h, ciphertext['c1'], ciphertext['c2'], Aw, Bw]) 
	response = {
		'r': (wr - c * r) % p,
		'm': (wm - c * m) % p
	}
	return (c, response)


def verify_pi_prepare_obtain(params, gamma, ciphertext, pi_prepare_obtain):
	""" verify prepare issuance proof """
	(_, _, g, h) = params
	(c, r) = pi_prepare_obtain
	Aw = c * ciphertext['c1'] + r['r'] * g
	Bw = c * ciphertext['c2'] + r['r'] * gamma + r['m'] * g
	return c == to_challenge([g, h, ciphertext['c1'], ciphertext['c2'], Aw, Bw])


# TODO: make bsk not contain prefix b in key (reduntant and inconsistant)
def make_pi_issue(params, sk, iparams={}, gamma=None, ciphertext={}, b=None, 
	bsk={}, r=None):
	""" make issuance proof """
	(_,p,g,h) = params
	assert iparams and gamma and b and r and ciphertext
	#create the witnesses
	w = {k:p.random() for k in (sk | bsk | {'b':1,'r':2})}
	Aw = w['x0']  * g + w['x0_tilde'] * h
	Bw = w['b']   * g
	Cw = w['bx0'] * g + w['bx0_tilde'] * h
	Dw = w['b']   * iparams['Cx0']
	Ew = w['x1']  * h
	Fw = w['bx1'] * h
	Gw = w['b']   * iparams['X1']
	Hw = w['r']   * g + w['bx1'] * ciphertext['c1'] 
	Iw = w['r']   * gamma + w['bx0'] * g + w['bx1'] * ciphertext['c2']
	c = to_challenge([g,h,Aw,Bw,Cw,Dw,Ew,Fw,Gw,Hw,Iw])
	response = {
		'x0' : (w['x0']  - c * sk['x0']) % p, 
		'x1' : (w['x1']  - c * sk['x1']) % p,
		'b'  : (w['b']   - c * b) % p,
		'bx0': (w['bx0'] - c * bsk['bx0']) % p,
		'bx1': (w['bx1'] - c * bsk['bx1']) % p,
		'bx0_tilde': (w['bx0_tilde'] - c * bsk['bx0_tilde']) % p,
		'x0_tilde' : (w['x0_tilde']  - c * sk['x0_tilde']) % p,
		'r': (w['r'] - c * r) % p
	}
	return (c,response)


def verify_pi_issue(params, iparams, u, e_u_prime, pi_issue, biparams=None, 
	gamma=None, ciphertext={}):
	""" verify issuance proof """
	assert iparams and u and e_u_prime and pi_issue 
	assert ciphertext and biparams and gamma
	(G, p, g, h) = params
	(c, r) = pi_issue
	Aw = r['x0'] * g + r['x0_tilde'] * h + c * iparams['Cx0']
	Bw = r['b'] * g + c * u
	Cw = r['bx0'] * g + r['bx0_tilde'] * h + c * biparams['bCx0']
	Dw = r['b'] * iparams['Cx0'] + c * biparams['bCx0']
	Ew = r['x1'] * h + c * iparams['X1']
	Fw = r['bx1'] * h + c * biparams['bX1']
	Gw = r['b'] * iparams['X1'] + c * biparams['bX1']
	Hw = r['r'] * g + r['bx1'] * ciphertext['c1'] + c * e_u_prime['c1']
	Iw = r['r'] * gamma + r['bx0'] * g + r['bx1'] * ciphertext['c2'] + c * e_u_prime['c2']
	return c == to_challenge([g,h,Aw,Bw,Cw,Dw,Ew,Fw,Gw,Hw,Iw])


def make_pi_show(params, iparams, m, r, z, sigma):
	""" make credentials showing proof """
	(_, p, g, h) = params
	(u, Cm, Cu_prime) = sigma
	(wr,wz,wm) = (p.random(),p.random(),p.random())
	Cm_tilde = wm * u + wz * h
	V_tilde = wz * iparams['X1'] + wr * g
	c = to_challenge([g,h,Cm,Cu_prime,Cm_tilde,V_tilde])
	r = {'r': (wr + c*r) % p,
		 'm': (wm - c*m) % p,
		 'z': (wz - c*z) % p}
	return (c, r)


def verify_pi_show(params, iparams, sigma, pi_show, V):
	""" verify credentials showing proof """
	assert iparams and sigma and pi_show
	(_, _, g, h) = params
	(u, Cm, Cu_prime) = sigma
	assert u and Cu_prime
	(c, r) = pi_show
	Cm_tilde = r['m'] * u + r['z'] * h + c * Cm
	V_tilde  = r['r'] * g + r['z'] * iparams['X1'] + c * V
	return c == to_challenge([g, h, Cm, Cu_prime, Cm_tilde, V_tilde])










	





