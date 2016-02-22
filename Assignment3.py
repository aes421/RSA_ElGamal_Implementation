from random import randint

'''def RSA_sign(text, d, n):
	return (text**d) % n

def RSA_sign_verify(signature, e, n):
	return (signature**e) % n'''

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

def find_multiplicative_inverse(euler_totient):
	inverse1 = 54#randint(2,euler_totient-1)
	inverse2 = None
	while (inverse2 is None):
		inverse1 = randint(2,euler_totient-1)
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
	private_key = 43 #randint(1,100)
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

def ElGamal_encrypt(plaintext, prime1, prime2, public_key):
	k = 5#randint(1, prime1)
	cipher = (plaintext * (public_key**k)) % prime1
	u = (prime2 ** k) % prime1
	print "u = g^k = ", prime2, "^", k, " = ", u, " mod ", prime1 
	print "public key = ", public_key, "^", k, " = ", (public_key**k)%prime1 ," mod ", prime1
	print "C = ", plaintext, "x", (public_key**k)%prime1, " = ", cipher, " mod ", prime1
	return cipher, u, k

def ElGamal_decrypt(ciphertext, u, private_key, public_key, k, prime1):
	x = u**private_key
	print "u^a = ", u, " ^ ", private_key, " = ", x%prime1, " mod p"
	inverse1, inverse2 = find_multiplicative_inverse(prime1)
	plaintext = (ciphertext * inverse2)%prime1
	print "decryption: ", plaintext
	return plaintext

def rsa_main():
	plaintext = input("Please enter a number for your message: ")
	prime1, prime2 = choose_primes()
	public1, public2, private = RSA_compute_keys(prime1, prime2)
	print "PERSON ONE SENDS:", plaintext 
	#signature = RSA_sign(plaintext, private, public1)
	#print "SIGNATURE IS: ", signature
	cipher = RSA_encrypt(public1, public2, plaintext)
	print "PERSON TWO RECIEVES: ", cipher
	decrypted_msg = RSA_decrypt(private, public1, cipher)
	#verification = RSA_sign_verify(signature, public2, public1)
	#print "SIGNATURE VERIFICATION: ", verification


def gamal_main():
	plaintext = input("Please enter a number for your message: ")
	prime1, prime2 = choose_primes()
	private_key, public_key = ElGamal_compute_keys(prime1, prime2)
	print "PERSON ONE SENDS:", plaintext 
	cipher, u, k = ElGamal_encrypt(plaintext, prime1, prime2, public_key)
	print "PERSON TWO RECIEVES: ", cipher, "and", u
	decrypted_msg = ElGamal_decrypt(cipher, u, private_key, public_key, k, prime1)



#rsa_main()
gamal_main()
