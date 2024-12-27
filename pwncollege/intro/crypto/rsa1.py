from base64 import b64decode
from Crypto.PublicKey import RSA



# key = RSA.generate(2048)
# print(f"(public)  n = {key.n:#x}")
# print(f"(public)  e = {key.e:#x}")
# print(f"(private) d = {key.d:#x}")


# ciphertext = pow(int.from_bytes(flag, "little"), key.e, key.n).to_bytes(256, "little")
# print(f"Flag Ciphertext (b64): {b64encode(ciphertext).decode()}")

n = 0xb6317ec3b85802598e0dbac42af16215663f91de1a7c38e0902341136f6a9c44edc2957f4729b86a16180f5183fef64ff9b1ddfd3747420ea789226dc0ffffede08a2256975db689c05b5d77c1cecb835420cb213096fa2c745550a6af11250fc7501e55f59721d7eb5fcd82a00940f203787b4665b33f7678efdf2778463099dbcba3f3d86e2deb2346b4cd256bc9c8d54a75d7d4e8fdeebe2bea13b4a1bf3e2da653ed4af85be4b3f5eb7159c58e91a7efd778b94a3ee987088720b2b57f4d05afae5dc3b30fc5b06d3a9ff64dc40f2dcbb973df457a88c63b6195b92c3cfcbdf4f15a959096ac1d5c2bb5acd4f9b545d1d21ddc8fc3df9054110c27f6c5e1
e = 0x10001
d = 0x3ab2737ea6d363de6a4fae0e292f9f43f9af1d558afede6c2ac3d0e16c11d2caba36e8671b0c2be7b1ba8aa4de7bb3eb4c2cabb23aaef06f3c36882b07f4f20537440990103016f10651e928fdfd9bbf71c926e848793b9c3ad689a749dba22f152d90b86ce905f444569725305e0ad86d99d14d7ad266edca44ad864fcf7d34693a62ba2ea3d3a0c3597218900f207dd72119f2b371ecfd0ccfc6948e971bbae99445c5d7c6fa14ac9b0e5aa6f44013d6d5d6e0b33cc561cf04bb488356fd76308f523cb95df03a55d07de42fbe97773e940d47d92e74e62af9a14d84291d5be9fe3d7cbc24659668d65799a258eb1841aad24a4d062f9c0fc0d5758237e369

ciphertext_bs4 = "VI32B/4KsSVv6roeqn3XqvZzDYu6XS8ty0HIHOz0UjdMHi0dGY4UengH5IRZB/kS4ec6VmCJuz/Icey5ePtQ63kcB9hFuuXRr0aMdudRYJPB6R+Jc9ScrwuR296GzqRrLVmElQaNXb8jD+5stVhYI0QEZn/Y055SN1Z9MGYQUvY9/x0mqi30h4Ix+srp3iC8tpPYZ13O7aytEiwvsu3CJpB1qMvYcClzNAMIG3fQsl2LaF3eJ9Tu0GsNkiq9tIvG9KOl19HA2ypkSfF++78EkgR0nD7nClV8wCHKOpwH81hkjWYhRJVrjUMGWkEUuZO5inrlsWAgCXV21eitoCddsg=="
ciphertext = b64decode(ciphertext_bs4)

text = pow(int.from_bytes(ciphertext, "little"), d, n)
text.to_bytes(256, "little")
