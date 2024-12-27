import sys

from base64 import b64encode
from base64 import b64decode

n = int(open("/challenge/key-n").read(), 16)

signature = b"flag"
m = int.from_bytes(signature, "little")
i = 10

print(i, m//i)

print(b64encode(i.to_bytes(1, "little")))
print(b64encode((m//i).to_bytes(4, "little")))

a = b"tcflt0gVJVB0WtI4b0SNb8YUQr7pYY8hUmvHSkCiwilnGc2P4TWq/aE2WIepapSX0JNcgnZucsCMgLvE7lozqHoUzR0jNxK+STuJpGXZG5oEbGrPpVoO9x7zgerKC1vXaFt1e7kBMbeNyBl2Xa2hcSqPjw4W5buH1S3xRx9TKqfjj0//GGap0NWqgdZuUBDPe8LuiBCj2/MMzOleyqWy/kYo8JA/EWYxhNnSpkhfI+Wa4uVOWvS9TZ2nN21PE5tvIgyWfRfo3pzTiq3OZ183nbedFqiZz1eMfIqljqbsL/2X5GfC/nQ+QoCI2W0/BHdURM7ABLSl5Tc53/YKyUGtrA=="
b = b"VMRjkRr/Z+2H+KocP8UsZb5Deyw9LGOrKc79QEgbOUMb8x92fPIRZLLM9tPsIbbGT1D+Z4OSieceQ9CbxraxqZK7tfoeiZSOeHi7dQ4hKhMR4OFMCxmdrnwOvkahkahirc3ts6UfSFYPM22QdbeOsWTWIpshfF0mt0eV5DjMh+Lnp5yQJQaUTvz0DxsyAAzmkjXi0Kvda1xpK9xBBOaJ1vWS6i0kvr+J7TOCAWStMMj08JZelLnDsVYWcSS7L1PVVvR8W10Bz9mhMzQUrB/b47uie3QAnz94DdGbmvhfKoizGYSwXn2UfbuuDy1DJaqxMuAknw4p8ri+aHA9hRpimw=="

a = int.from_bytes(b64decode(a), "little")
b = int.from_bytes(b64decode(b), "little")



# command = pow(m, e, n).to_bytes(256, "little").rstrip(b"\x00")
print(f"Signed command (b64): {b64encode(((a*b)%n).to_bytes(256, "little").rstrip(b"\x00")).decode()}")