from random import randint
import hashlib

def RSA_sign(text, d, n):
	#hash_text = hashlib.md5(str(text))
	return (text**d) % n

def RSA_sign_verify(signature, e, n):
	return (signature**e) % n

def ElGamal_sign(text, prime1, prime2, private_key):
	temp = prime1 - 1
	#T0-DO: if no inverse is found change k
	inverse2 = None
	while (inverse2 == None):
		k = randint(1, temp)
		inverse1, inverse2 = find_multiplicative_inverse(temp, k)
	u = (prime2**k) % prime1
	print "u = g^k = ", prime2, "^", k, " = ", u, " mod ", prime1
	print "k^-1 = ", inverse2, " mod ", temp
	signature = ((text - (private_key*u))* inverse2) % temp
	print "\nS = (M-au)k^-1 = (", text, " - ", private_key, "x", u, ") x", inverse2, " = ", signature, " mod ", temp 
	return signature, k

#u = g^k mod p
#public_key(alpha) = g^a mod prime1
def ElGamal_sign_verify(text, signature, u, public_key, prime1, prime2):
	verification = ((public_key**u)*(u**signature)) % prime1
	print "\n(alpha^u)*(u^S) = (", public_key, "^", u, ") x (", u, "^", signature, ") = ", verification, " mod ", prime1 
	gm = (prime2**text) % prime1
	print "g^m = ", prime2, "^", text, "=", gm, " mod ", prime1
	return verification

#Source for ExtEuclideanAlg and modInvEuclid from https://numericalrecipes.wordpress.com/tag/modular-multiplicative-inverse/
def extEuclideanAlg(a, b) :
    """
    Computes a solution  to a x + b y = gcd(a,b), as well as gcd(a,b)
    """
    if b == 0 :
        return 1,0,a
    else :
        x, y, gcd = extEuclideanAlg(b, a % b)
        return y, x - y * (a // b),gcd
 
def modInvEuclid(a,m) :
    """
    Computes the modular multiplicative inverse of a modulo m,
    using the extended Euclidean algorithm
    """
    x,y,gcd = extEuclideanAlg(a,m)
    if gcd == 1 :
        return x % m
    else :
        return None

def find_multiplicative_inverse(euler_totient, inverse1 = None):
	inverse2 = None

	if inverse1 == None:
		inverse1 = randint(2,euler_totient-1)
		while (inverse2 is None):
			inverse1 = randint(2,euler_totient-1)
			inverse2 = modInvEuclid(inverse1, euler_totient)
	else:
		inverse2 = modInvEuclid(inverse1, euler_totient)
	return inverse1, inverse2

def choose_primes():
	number1 = input("Please enter a 4 digit prime: ")
	number2 = input("Please enter a second 4 digit prime: ")
	return number1, number2

def RSA_compute_keys(p, q):
	n = p*q
	euler_totient = (p-1)*(q-1)
	e, d = find_multiplicative_inverse(euler_totient)
	return n, e, d

def ElGamal_compute_keys(p,g):
	private_key = randint(1,p-1)
	public_key = (g**private_key)%p
	return private_key, public_key

def RSA_encrypt(key1, key2, plaintext):
	cipher = (plaintext**key2) % key1
	print "encryption: ", plaintext, "^", key2, "mod", key1, "=", cipher
	return cipher

def RSA_decrypt(private, key1, cipher):
	msg = (cipher**private) % key1
	print "decryption:", cipher, "^", private, "mod", key1, "=", msg
	return msg

def ElGamal_encrypt(plaintext, prime1, prime2, public_key, k):
	cipher = (plaintext * (public_key**k)) % prime1
	u = (prime2 ** k) % prime1
	print "u = g^k = ", prime2, "^", k, " = ", u, " mod ", prime1 
	print "public key = ", public_key, "^", k, " = ", (public_key**k)%prime1 ," mod ", prime1
	print "C = ", plaintext, "x", (public_key**k)%prime1, " = ", cipher, " mod ", prime1
	return cipher, u

def ElGamal_decrypt(ciphertext, u, private_key, public_key, k, prime1):
	x = (u**private_key)%prime1
	print "u^a = ", u, " ^ ", private_key, " = ", x, " mod p"
	inverse1, inverse2 = find_multiplicative_inverse(prime1, x)
	print x%prime1, "^-1 = ", inverse2, " mod p"
	plaintext = (ciphertext * inverse2)%prime1
	print "P = C(u^a)^-1 = ", ciphertext, "x", inverse2, " = ", plaintext, " mod p"
	print "decryption: ", plaintext
	return plaintext

def rsa_main():
	plaintext = input("Please enter a number for your message: ")
	prime1, prime2 = choose_primes()
	public1, public2, private = RSA_compute_keys(prime1, prime2)
	print "PERSON ONE SENDS:", plaintext 
	print("\n")
	signature = RSA_sign(plaintext, private, public1)
	print "SIGNATURE IS: ", signature
	cipher = RSA_encrypt(public1, public2, plaintext)
	print("\n")
	print "PERSON TWO RECIEVES: ", cipher
	decrypted_msg = RSA_decrypt(private, public1, cipher)
	print("\n")
	verification = RSA_sign_verify(signature, public2, public1)
	print "SIGNATURE VERIFICATION: ", verification, "\n\n"


def gamal_main():
	plaintext = input("Please enter a number for your message: ")
	prime1, prime2 = choose_primes()
	private_key, public_key = ElGamal_compute_keys(prime1, prime2)
	print "\n\nPERSON ONE SENDS:", plaintext 
	signature, k = ElGamal_sign(plaintext, prime1, prime2, private_key)
	print "SIGNATURE IS: ", signature, "\n"
	
	cipher, u= ElGamal_encrypt(plaintext, prime1, prime2, public_key, k)

	print "\nPERSON TWO RECIEVES: ", cipher, "and", u
	decrypted_msg = ElGamal_decrypt(cipher, u, private_key, public_key, k, prime1)
	verification = ElGamal_sign_verify(plaintext, signature, u, public_key, prime1, prime2)
	print "SIGNATURE VERIFICATION: ", verification, "\n\n"




answer = None
while (answer != 0):
	answer = input("Press 0 to exit\nPress 1 for RSA\nPress 2 for El Gamal\n")
	if (answer == 1):
		rsa_main()
	elif (answer == 2):
		gamal_main()
