---
layout: post
title: AngstromCTF 2020 - One Time Bad
excerpt: "Writeup for one time pad challenge from AngstromCTF 2020"
categories: [crypto]
---

One Time Bad was the fifth challenge from AngstromCTF 2020. The challenge provides us with some python code (below) and a challenge server. 

{% highlight python %}

import random, time
import string
import base64
import os

def otp(a, b):
	r = ""
	for i, j in zip(a, b):
		r += chr(ord(i) ^ ord(j))
	return r


def genSample():
	p = ''.join([string.ascii_letters[random.randint(0, len(string.ascii_letters)-1)] for _ in range(random.randint(1, 30))])
	k = ''.join([string.ascii_letters[random.randint(0, len(string.ascii_letters)-1)] for _ in range(len(p))])

	x = otp(p, k)

	return x, p, k

random.seed(int(time.time()))

print("Welcome to my one time pad service!\nIt's so unbreakable that *if* you do manage to decrypt my text, I'll give you a flag!")
print("You will be given the ciphertext and key for samples, and the ciphertext for when you try to decrypt. All will be given in base 64, but when you enter your answer, give it in ASCII.")
print("Enter:")
print("\t1) Request sample")
print("\t2) Try your luck at decrypting something!")

while True:
	choice = int(input("> "))
	if choice == 1:
		x, p, k = genSample()
		print(base64.b64encode(x.encode()).decode(), "with key", base64.b64encode(k.encode()).decode())

	elif choice == 2:
		x, p, k = genSample()
		print(base64.b64encode(x.encode()).decode())
		a = input("Your answer: ").strip()
		if a == p:
			print(os.environ.get("FLAG"))
			break

		else:
			print("Wrong! The correct answer was", p, "with key", k)

{% endhighlight %}

Looking at the code it seems to use a [one time pad](https://en.wikipedia.org/wiki/One-time_pad), XORing the variable p with the variable k resulting in x. The script gives us this variable x and expects us to recover p. This task seems impossible since a one time pad offers perfect secrecy. Without knowing any other information, there is an infinite search space - p and k could have been anything! Looking closer at the code though, we can see that random is seeded in an unusual way. 

{% highlight python %}

random.seed(int(time.time()))

{% endhighlight %}

Since random is seeded based off of the time, we can do the same in a script on our end. If our python random generator is seeded the same as the server's random generator, all variables in the script will be generated identically. This will allow us to emulate the challenge in our solve script in order to predict the value of p to get the flag. This is illustrated in the below script, where I recycled some functions from the challenge source. 

{% highlight python %}

from pwn import * 
import base64
import random
import time

def otp(a, b):
	# XORs strings a and b
	r = ""
	for i, j in zip(a, b):
		r += chr(ord(i) ^ ord(j))
	return r


def genSample():
	# two random samples of ascii letters
	p = ''.join([string.ascii_letters[random.randint(0, len(string.ascii_letters)-1)] for _ in range(random.randint(1, 30))])
	k = ''.join([string.ascii_letters[random.randint(0, len(string.ascii_letters)-1)] for _ in range(len(p))])

	# otp with random strings
	x = otp(p, k)

	return x, p, k



r = remote('misc.2020.chall.actf.co', 20301)
random.seed(int(time.time())) # seed the same as the challenge server

r.sendline('2') # option two to decrypt for flag

x, p, k = genSample() # will be equal to the values on the challenge server

r.sendline(p)

r.interactive()

{% endhighlight %}

The output of the script is seen below.

```
michael@computer:~/Documents/CTF/angstrom/otb_COMPLETE$ python3 onebad.py 
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/michael/.pwntools-cache-3.6/update to 'never'.
[*] You have the latest version of Pwntools (4.0.1)
[+] Opening connection to misc.2020.chall.actf.co on port 20301: Done
[*] Switching to interactive mode
Welcome to my one time pad service!
It's so unbreakable that *if* you do manage to decrypt my text, I'll give you a flag!
You will be given the ciphertext and key for samples, and the ciphertext for when you try to decrypt. All will be given in base 64, but when you enter your answer, give it in ASCII.
Enter:
    1) Request sample
    2) Try your luck at decrypting something!
> Hw==
Your answer: actf{one_time_pad_more_like_i_dont_like_crypto-1982309}
[*] Got EOF while reading in interactive
```

This gives us the flag `actf{one_time_pad_more_like_i_dont_like_crypto-1982309}`! Keep in mind that this challenge would have been harder if random was seeded based off of the EXACT time given by python, but since it was casted as an integer, we only had to be accurate to the second.