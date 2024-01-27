primes = {
	14: {
	"prime": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
	"generator": 2
	},
}

import os
import binascii
import hashlib

class DH:
	def __init__(self, group=14):
		if group in primes:
			self.p = primes[group]["prime"]
			self.g = primes[group]["generator"]
		else:
			raise Exception("Invalid Group")
		self.__a = int(binascii.hexlify(os.urandom(32)), base=16)

	def pub_key_generate(self):
		return pow(self.g, self.__a, self.p)

	def key_public_check(self, pub_key):
		if 2 <= pub_key and pub_key <= self.p - 2:
			if pow(pub_key, (self.p - 1) // 2, self.p) == 1:
				return True
		return False

	def gen_shared_key(self, pub_key):
		if self.key_public_check(pub_key):
			self.shared_key = pow(pub_key, self.__a, self.p)
			return hashlib.sha256(str(self.shared_key).encode()).hexdigest()
		else:
			raise Exception("Bad public key")