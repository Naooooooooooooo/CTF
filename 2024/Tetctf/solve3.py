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
               #b *(note_sync + 547)
               #b *(add_new_note + 316)
               c''')
def GDB_backend(proc):
    gdb.attach(proc, gdbscript='''
               #b NoteBackend_init
               b memcpy
               c''')
def GDB_All():
    GDB(p)
    GDB_backend(pidof('backend'))
    
    
p = process(['./interface', './backend'])
new_note(b'a', b'a', 1, b'a', b'a')
GDB_All()
pause()
read_note(b'a', b'a', b'a')


p.interactive()



