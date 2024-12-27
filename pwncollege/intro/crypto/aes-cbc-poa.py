
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
concatenating the two blocks. If O(ZIV|Cn) == 1 then Xn ^ ZIV ends with valid padding. The padding va>
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
"""

# handle dispatcher
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

	os.execv("/challenge/dispatcher", ["/challenge/disptacher", "flag"])
	print("Error execv.", file=sys.stderr)
	exit(1)

os.close(w)

read_file = os.fdopen(r, "r")
ct = b64decode(read_file.readline().split()[1])
read_file.close()
os.waitpid(pid,0)
assert len(ct) % BLOCK_SIZE == 0, "ensure the cts block size is 16 or adjust the block size"
blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
print(f"Intercepted dispatched ciphertext blocks: {blocks}")

# handle worker
def do_oracle(msg):
	valid_padding = False
	pat0 = re.compile("ValueError.*\n")
	pat1 = re.compile("Sleeping!\n")
	pat2 = re.compile("Unknown command!\n")
	pat3 = re.compile("Not so easy.*\n")
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

	write_file.write("TASK: "+b64encode(msg).decode()+"\n")

	while True:
		line = read_file.readline()

		if pat0.match(line):
			break

		if pat1.match(line) or pat2.match(line) or pat3.match(line):
			valid_padding = True
			os.kill(pid, signal.SIGTERM)
			break

	os.waitpid(pid, 0)
	return valid_padding

flag = b""
iiv = blocks[0]

for ct in blocks[1:]:
	# single block attack
	ziv = [0]*BLOCK_SIZE
	print(f"IIV: {iiv}, CT: {ct}")
	print(f"Current zeroing_iv: {bytes(ziv)}")
	for pad_val in range(1, BLOCK_SIZE+1):
		padding_iv = [pad_val ^ cur_byte for cur_byte in ziv]

		for candidate in range(256):
			padding_iv[-pad_val] = candidate
			if do_oracle(bytes(padding_iv)+ct):
				if pad_val == 1:
					# make sure the padding really is of length 1 by changing
					# the penultimate byte and querying the oracle again
					padding_iv[-2] ^= 1
					if not do_oracle(bytes(padding_iv)+ct):
						print("False positive.")
						continue
				break

		# set respective zeroing_iv byte to x
		# this in turn will be xored with the expected padding byte for the next iteration
		# and always result in the correct padding value x ^ x ^ pad_val = pad_val
		ziv[-pad_val] = candidate ^ pad_val
		print(f"Current zeroing_iv: {bytes(ziv)}")
		print(f"Current palintext byte: {bytes([(ziv[-pad_val] ^ iiv[-pad_val])])}")

	flag += bytes([ziv_byte ^ iv_byte for ziv_byte, iv_byte in zip(ziv, iiv)])
	print(flag)
	iiv = ct

# from base64 import b64decode, b64encode
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import unpad
# from pwn import *

# def flip(byte_value, bit_pos):
#     return byte_value ^ (1 << bit_pos)

# def generate_cookie(original_enstr):
#     enstr = base64.b64decode(original_enstr)
#     enstrs = []
#     for i in range(len(enstr)):
#         for bit in range(8):
#             f = flip(enstr[i], bit).to_bytes(1)
#             new = enstr[:i] + f + enstr[i+1:]
#             enstrs.append(base64.b64encode(new))
#     return enstrs

# def bit_flip_attack():
#     original_enstr = "k4eKMB+SxYs/grf8UbGQTe/GttP+02swmsJADq5Kh3/ICnqvT5OZQXCU3RDwbjImCRgQjcjzoKhu6BBN78dtw30dsQi/XOh5iAGySy0NG+g="
#     enstrs = generate_cookie(original_enstr)
#     for enstr in enstrs:
#         p = process("/challenge/worker")
#         sleep(0.2)
#         p.sendline(enstr)
#         sleep(0.2)
#         a = p.recvuntil("\n")
#         if a.find("Unknown"):
#             break
#         p.close()
# bit_flip_attack()