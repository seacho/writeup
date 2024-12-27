import base64
import os
import re
from Crypto.Hash.SHA256 import SHA256Hash


"""
    difficulty = 2

    challenge = get_random_bytes(32)
    show_b64("challenge", challenge)

    response = input_b64("response")
    if SHA256Hash(challenge + response).digest()[:difficulty] == (b'\0' * difficulty):
        show("flag", flag.decode())
"""


prefix = b"\0" * 2
pat0 = re.compile(r".*challenge \(b64\): (.*)")
r_pipe0, w_pipe0 = os.pipe()
r_pipe1, w_pipe1 = os.pipe()

pid = os.fork()

if pid == -1:
    print("Erro fork.")
    exit(1)

if pid == 0:
    os.close(w_pipe0)
    os.close(r_pipe1)

    os.dup2(r_pipe0, 0)
    os.close(r_pipe0)

    os.dup2(w_pipe1, 1)
    os.close(w_pipe1)

    os.execv("/challenge/run", ["/challenge/run"])
    print("Error execv.")
    exit(1)

os.close(r_pipe0)
os.close(w_pipe1)

output = os.fdopen(r_pipe1, "r")
input = os.fdopen(w_pipe0, "wb")

while True:
    line = output.readline()
    print(line, end="")
    m = pat0.match(line)
    if m:
        challenge = base64.standard_b64decode(m.group(1))
        print(f"Got challenge {challenge}")
        i = 0
        while True:
            sha256 = SHA256Hash(challenge + str(i).encode("utf-8")).digest()
            print(f"Compare i {i} sha256[:2] {sha256[:2]} to {prefix}")
            if sha256[:2] == prefix:
                input.write(base64.standard_b64encode(str(i).encode("utf-8")) + b"\n")
                input.flush()
                break
            i += 1