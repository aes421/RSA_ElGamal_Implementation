from random import randint

def gcd(e, i):
	temp1 = e
	temp2 = i
	remainder = temp1%temp2
	while(remainder != 0):	
		temp1 = temp2
		temp2 = remainder
		remainder = temp1%temp2

	return temp1

def find_multiplicative_inverse(euler_totient):
	inverse1 = 5 #randint(2,9)
	inverse2 = 0
	for each in xrange(0, euler_totient):
		answer = (inverse1*each) % euler_totient
		if answer == 1:
			inverse2 = each
			break
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
	cipher = encrypt(public1, public2, plaintext)
	print "PERSON TWO RECIEVES: ", cipher
	decrypted_msg = decrypt(private, public1, cipher)
	print (decrypted_msg)

rsa_main()
