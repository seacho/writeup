def gcd(a, b):
    dividend = max(a, b)
    divisor = min(a, b)
    rem = 0
    while True:
        rem = dividend % divisor
        if rem == 0:
            return divisor
        dividend = divisor
        divisor = rem

# a?u+b?v=gcd(a,b)
def extended_euclid(a, b):
    if b == 0:
        return (1, 0, a)
    else:
        (x, y, q) = extended_euclid(b, a % b)
        return (y, x - (a // b) * y, q)
 
# 使用示例
a = 32321
b = 26513
 
# 调用扩展欧几里得算法
x, y, gcd = extended_euclid(a, b)
print(f"GCD({a}, {b}) = {gcd}")
print(f"特解为 x = {x}, y = {y}")
