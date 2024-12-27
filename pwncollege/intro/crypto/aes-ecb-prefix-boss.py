import requests
import base64

url = "http://challenge.localhost:80"

# Step 1: Determine block size
def detect_block_size():
    base_length = len(get_ciphertext(""))
    for i in range(1, 33):  # Test input sizes up to 32 bytes
        new_length = len(get_ciphertext("A" * i))
        if new_length > base_length:
            return new_length - base_length
    return None

def get_ciphertext(input_data):
    response = requests.post(url, data={"content": input_data})
    encrypted = response.text.split("<pre>")[1].split("</pre>")[0]
    return base64.b64decode(encrypted)

# Step 2: Get ciphertext for input
def get_ciphertext(input_data):
    response = requests.post(url, data={"content": input_data})
    requests.post(url+"/reset")
    encrypted = response.text.split("<pre>")[1].split("</pre>")[0]
    return base64.b64decode(encrypted)

# Step 3: Extract flag
def extract_flag(block_size):
    known_flag = b""
    while True:
        block_start = len(known_flag) // block_size * block_size
        crafted_input = "A" * (block_size - (len(known_flag) % block_size) - 1)
        base_ciphertext = get_ciphertext(crafted_input)
        
        for i in range(256):
            test_input = crafted_input + known_flag.decode() + chr(i)
            test_ciphertext = get_ciphertext(test_input)

            if test_ciphertext[:block_start + block_size] == base_ciphertext[:block_start + block_size]:
                known_flag += bytes([i])
                print(f"Known flag: {known_flag.decode(errors='ignore')}")
                break
        else:
            # No match, flag extraction complete
            break
    return known_flag.decode()

# Main logic
if __name__ == "__main__":
    block_size = 16#detect_block_size()
    print(f"Detected block size: {block_size}")
    flag = extract_flag(block_size)
    print(f"Extracted flag: {flag}")
