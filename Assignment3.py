from random import randint

'''def RSA_sign(text, d, n):
	return (text^d) % n

def RSA_sign_verify(signature, e, d):
	return (text^e) % n'''

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
	inverse1 = randint(2,euler_totient-1)
	inverse2 = None
	while (inverse2 is None):
		inverse1 = randint(2,euler_totient-1)
		inverse2 = modInvEuclid(inverse1, euler_totient)
	return inverse1, inverse2

def choose_primes():
	number1 = input("Please enter a 4 digit prime: ")
	number2 = input("Please enter a second 4 digit prime: ")
	return number1, number2

def compute_keys(p, q):
	n = p*q
	euler_totient = (p-1)*(q-1)
	e, d = find_multiplicative_inverse(euler_totient)
	return n, e, d

def encrypt(key1, key2, plaintext):
	cipher = (plaintext**key2) % key1
	print "encryption: ", plaintext, "^", key2, "mod", key1, "=", cipher
	return cipher

def decrypt(private, key1, cipher):
	msg = (cipher**private) % key1
	print "decryption:", cipher, "^", private, "mod", key1, "=", msg
	return msg

def rsa_main():
	plaintext = input("Please enter a number: ")
	prime1, prime2 = choose_primes()
	public1, public2, private = compute_keys(prime1, prime2)
	print "PERSON ONE SENDS:", plaintext 
	#signature = RSA_sign(plaintext, private, public1)
	#print "SIGNATURE IS: ", signature
	cipher = encrypt(public1, public2, plaintext)
	print "PERSON TWO RECIEVES: ", cipher
	decrypted_msg = decrypt(private, public1, cipher)
	#verification = RSA_sign_verify(signature, public2, public1)
	#print "SIGNATURE VERIFICATION: ", verification

rsa_main()
