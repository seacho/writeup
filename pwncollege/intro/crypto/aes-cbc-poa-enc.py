import os
import re
import signal
import sys
import time
from base64 import b64decode, b64encode


"""
Theory:
With a padding oracle attack we can decrypt any block of ciphertext n by manipulating the previous
ciphertext block n-1.
Pn = Dk(Cn) ^ Cn-1
C0 = IV
For simplicity we let Dk(Cn) be Xn.
Since this is a chosen-ciphertext attack, we have control over the entire ciphertext message.
We can change the value of Cn-1 to anything. We do not change Cn. This ensures, that Xn remains the
same. If we can figure out Xn using the padding oracle, we can deduce Pn by calculating Xn ^ Cn-1
without any knowledge about the key k. For better readability we call Cn-1 IIV from here on.

Since we never change Cn and thus Xn, any change to a byte i of IIV changes the byte i of Pn.
p1,...,pi = x1,...,xi ^ iiv1,...,iivi

The oracle:
Given a block sequence of bytes Y = y1,...,yn, we define an oracle O(Y) which yields 1 if the
decryption in CBC mode has correct padding.

Last byte oracle:
For block n we compute the last byte Xn. We call it the last byte oracle.
Let ziv1,...,zivi be random bytes and let ZIV = ziv1,...,zivi. We forge a fake ciphertext ZIV|Cn by
concatenating the two blocks. If O(ZIV|Cn) == 1 then Xn ^ ZIV ends with valid padding. The padding value is most likely 1. Only for the last byte the padding value is not guaranteed.
Pn contains random plaintext bytes p1,..,pi-1. If pi-1 is 2, a value of 2 for pi would also result in
valid padding. We can check this by running the same oracle again, but this time with a different
value for pi-1. If O(ZIV'|Cn) == 1, the padding value must be 1.
If O is ever != 1, we adjust the last byte of ZIV to a different value. In the worst case this means,
that the last byte take on all values from 0-255 until O evaluates to 1.
x1,...,xi = pziv1,...,1 ^ ziv1,...,zivi
We can calculate xi = 1 ^ zivi.
We can calculate pi = zivi ^ iivi, since xi is the same value in both cases due to Cn never changing.

We iteratively reapeat the oracle for all remaining bytes 1,...,i-1.
We adjust ZIV = ziv1,...,zivi-1, xi ^ 2. This ensures pzivi will be 2, since xi ^ xi ^ 2 = 2.
It also ensures pzivi-1 = 2 if O(ZIV|Cn) == 1, since 22 is the only combination of valid padding.

Due to the nature of aes any byte sequence of a valid block size is also valid ciphertext. This does
not mean, that the decrypted plaintext is valid ciphertext however due to padding rules and standards.
The important takeaway from this is, that any manipulated block of ciphertext can be decrypted to
some plaintext.

We can encrypt any plaintext using a padding oracle. Starting at the last block n of ciphertext
intercepted, we use the padding oracle O(ZIV|Cn) to deduce Xn. We then craft a cipherblock n-1 ,such
that Cn-1 = Xn ^ Pn, with Pn equal to the last block of plaintext we want to encrypt.
We then deduce Xn-1 via O(ZIV|Cn-1) and craft Cn-2 = Xn-1 ^ Pn-1, where Pn-1 is the penultimate block
of Plaintext we want to encrypt. We repeat this process until we have encrypted all blocks of our
desired plaintext.
"""

BLOCK_SIZE = 16
blocks = None
r, w = os.pipe()
pid = os.fork()

if pid == -1:
	print("Error fork.", file=sys.stderr)
	exit(1)

if pid == 0:
	os.close(r)

	os.dup2(w, 1)
	os.close(w)

	os.execv("/challenge/dispatcher", ["/challenge/dispatcher"])
	print("Error execv.", file=sys.stderr)
	exit(1)

os.close(w)

read_file = os.fdopen(r, "r")
ct = b64decode(read_file.readline().split()[1])
read_file.close()
os.waitpid(pid, 0) # prevent zombie
assert len(ct) % BLOCK_SIZE == 0, "Ciphertext length and block size do not match!"
blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
print(f"Intercepted dispatched ciphertext blocks: {blocks}")

def do_oracle(msg):
	pat0 = re.compile("ValueError.*\n")
	pat1 = re.compile("Sleeping!\n")
	pat2 = re.compile("Unknown command!\n")
	pat3 = re.compile("Victory! Your flag:\n")
	valid_padding = False
	mfd, sfd = os.openpty()
	pid = os.fork()

	if pid == -1:
		print("Error fork.", file=sys.stderr)
		exit(1)

	if pid == 0:
		os.close(mfd)

		os.dup2(sfd, 0)
		os.dup2(sfd, 1)
		os.dup2(sfd, 2)
		os.close(sfd)

		os.execv("/challenge/worker", ["/challenge/worker"])
		print("Error execv.", file=sys.stderr)
		exit(1)

	os.close(sfd)

	read_file = os.fdopen(mfd, "r")
	write_file = os.fdopen(mfd, "w")

	write_file.write(f"TASK: {b64encode(msg).decode()}\n")

	while True:
		line = read_file.readline()

		if pat0.match(line):
			break

		if pat1.match(line) or pat2.match(line):
			valid_padding = True
			os.kill(pid, signal.SIGTERM)
			break

		if pat3.match(line):
			valid_padding = True
			print(read_file.readline())
			os.kill(pid, signal.SIGTERM)
			break

	read_file.close()
	os.waitpid(pid, 0)
	return valid_padding


def attack_single_block(ct):
	ziv = [0]*BLOCK_SIZE
	print(f"Current ziv: {bytes(ziv)}")
	for pad_val in range(1, BLOCK_SIZE+1):
		piv = [pad_val ^ zero_val for zero_val in ziv]

		for candidate in range(256):
			piv[-pad_val] = candidate
			if do_oracle(bytes(piv)+ct):
				if pad_val == 1:
					piv[-2] ^= 1
					if not do_oracle(bytes(piv)+ct):
						continue
				break

		ziv[-pad_val] = candidate ^ pad_val # set x fo current block byte
		print(f"Current ziv: {bytes(ziv)}")

	return bytes(ziv)


# plaintext to encrypt
pt = b"please give me the flag, kind worker process!"
pad_val = BLOCK_SIZE - (len(pt) % BLOCK_SIZE)
pt += bytes([pad_val]*pad_val)
print(f"Plaintext to encrypt: {pt}")
pt_blocks = [pt[i:i+BLOCK_SIZE] for i in range(0, len(pt), BLOCK_SIZE)]
print(f"Plaintext blocks: {pt_blocks}")

ct = blocks[1]
manipulated_ct = blocks[1]
print(manipulated_ct)

for pt_block in pt_blocks[::-1]:
	x = attack_single_block(ct)
	print(f"Xn: {x}")
	ct = bytes([pt_val ^ x_val for pt_val, x_val in zip(pt_block, x)])
	print(f"IV: {ct} for C: {manipulated_ct}")
	manipulated_ct = ct + manipulated_ct
	print(f"Decrypting {manipulated_ct}")
	do_oracle(manipulated_ct)