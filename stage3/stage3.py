#!/usr/bin/env python3
import sys
import base64
import itertools
import string
from passlib.hash import argon2

DICTIONARY_PATH = 'dico.txt'

if __name__ == '__main__':
	salt_meteo=base64.b64decode('epXJYKkYSEXDBkRAuKCSig==')
	password_meteo='AlloBruineCrachin'
	hash_meteo="$argon2id$v=19$m=102400,t=2,p=8$epXJYKkYSEXDBkRAuKCSig$Bc8YbOHmrOeDiBygKFzkMw"

	salt_chat=base64.b64decode('ShgCOIbvVzVKtPEKEQge3g==')
	hash_chat="$argon2id$v=19$m=102400,t=2,p=8$ShgCOIbvVzVKtPEKEQge3g$zZwnq4W8H4LqtwiCSAULQQ"

	a = argon2.using(type='ID', salt=salt_meteo, rounds=2, memory_cost=102400, parallelism=8)
	assert(hash_meteo == a.hash(password_meteo))

	a = argon2.using(type='ID', salt=salt_chat, rounds=2, memory_cost=102400, parallelism=8)

	dico = {}
	with open(DICTIONARY_PATH, 'r') as f:
		for line in f:
			dico[line[0:1]] = line.strip()
	
	for combin in itertools.product(string.ascii_uppercase, repeat=3):
		password = ''.join((dico[combin[0]], dico[combin[1]], dico[combin[2]]))
		print(f'Trying password: {password}')
		if a.hash(password) == hash_chat:
			print(f'Password is {password}')       
			sys.exit(0)
	
	print('Could not find password for entry chat')
	sys.exit(1)
