#!/usr/bin/env python3

substitution_table = {}

# sstic
substitution_table[0x1f34c] = 's'
substitution_table[0x1f34d] = 't'
substitution_table[0x1f342] = 'i'
substitution_table[0x1f33c] = 'c'

# org
substitution_table[0x1f348]='o'
substitution_table[0x1f34b]='r'
substitution_table[0x1f340]='g'

# challenge
substitution_table[0x1f341] = 'h'
substitution_table[0x1f33a] = 'a'
substitution_table[0x1f345] = 'l'
substitution_table[0x1f33e] = 'e'
substitution_table[0x1f347] = 'n'

substitution_table[0x1f349] = 'p'
substitution_table[0x1f34f] = 'v'
substitution_table[0x1f346] = 'm'
substitution_table[0x1f34e] = 'u'
substitution_table[0x1f353] = 'z'
substitution_table[0x1f33b] = 'b'
substitution_table[0x1f33d] = 'd'
substitution_table[0x1f343] = 'j'
substitution_table[0x1f33f] = 'f'
substitution_table[0x1f351] = 'x'
substitution_table[0x1f352] = 'y'
substitution_table[0x1f34a] = 'q'

if __name__ == '__main__':

	with open('potager.txt', 'r') as f:
		content = f.read()
		text = ""
		for c in content:
			if ord(c) in substitution_table:
				text += substitution_table[ord(c)]
			elif ord(c) < 0xffff:
				text += c
			else:
				text += '[?={:x}]'.format(ord(c))
		print(text)
