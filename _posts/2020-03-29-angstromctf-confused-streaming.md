---
layout: post
title: AngstromCTF 2020 - Confused Streaming
excerpt: "Writeup for stream cipher cryptography challenge from AngstromCTF 2020"
categories: [crypto]
---

Confused Streaming was the fourth challenge from AngstromCTF 2020. The challenge provides us with some python code (seen below) and a challenge server. 

{% highlight python %}

from __future__ import print_function
import random,os,sys,binascii
from decimal import *
try:
	input = raw_input
except:
	pass
getcontext().prec = 1000
def keystream(key):
	random.seed(int(os.environ["seed"]))
	e = random.randint(100,1000)
	while 1:
		d = random.randint(1,100)
		ret = Decimal('0.'+str(key ** e).split('.')[-1])
		for i in range(d):
			ret*=2
		yield int((ret//1)%2)
		e+=1
try:
	a = int(input("a: "))
	b = int(input("b: "))
	c = int(input("c: "))
	# remove those pesky imaginary numbers, rationals, zeroes, integers, big numbers, etc
	if b*b < 4*a*c or a==0 or b==0 or c==0 or Decimal(b*b-4*a*c).sqrt().to_integral_value()**2==b*b-4*a*c or abs(a)>1000 or abs(b)>1000 or abs(c)>1000:
		raise Exception()
	key = (Decimal(b*b-4*a*c).sqrt() - Decimal(b))/Decimal(a*2)
except:
	print("bad key")
else:
	flag = binascii.hexlify(os.environ["flag"].encode())
	flag = bin(int(flag,16))[2:].zfill(len(flag)*4)
	ret = ""
	k = keystream(key)
	for i in flag:
		ret += str(next(k)^int(i))
	print(ret)

{% endhighlight %}

The code first seems to prompt the user for variables a, b, and c. This along with the use of square roots immediately reminded me of the [Quadratic Formula](https://en.wikipedia.org/wiki/Quadratic_formula) (seen below). In order to pass the "bad key" case we need to pass several checks relating to our choice of variables.

$$-b \pm \sqrt{b^2-4ac} \over 2a$$

We can pass the first check if the following is true.

$$b^2 \ge 4ac$$

This will eliminate the possiblilty of imaginary numbers that could come about by taking the square root of a negative number. The next three checks ensure that none of the variables are zero.(easy enough). The fifth check (seen below) is slightly more complicated.

$$\left(\sqrt{b^2-4ac}\right)^2 \ne b^2-4ac$$

At first glance it seems like this check will never be passed, but since the script uses python's [decimal](https://docs.python.org/2/library/decimal.html) library it is actually possible. The `getcontext().prec = 1000` line in the script tells us that it will round to 1000 decimal places, so whenever the square root returns something irrational, it will be rounded, and the square will not exactly equal the right side of the equation. This eliminates the possibility of any combinations with rational roots passing the check. Finally, the script makes sure that none of our variables exceed 1000.

Next, the key is set to the output of the quadratic equation with the chosen a, b, and c. The key cannot possibly be rational (within 1000 decimal digits, atleast) because of the reasons stated above. Now we can look at the next chunk of code (below). I moved the keystream function and the key definition closer together to make it more readable.

{% highlight python %}
def keystream(key):
	random.seed(int(os.environ["seed"]))
	e = random.randint(100,1000)
	while 1:
		d = random.randint(1,100)
		ret = Decimal('0.'+str(key ** e).split('.')[-1])
		for i in range(d):
			ret*=2
		yield int((ret//1)%2)
		e+=1

key = (Decimal(b*b-4*a*c).sqrt() - Decimal(b))/Decimal(a*2)
flag = binascii.hexlify(os.environ["flag"].encode())
flag = bin(int(flag,16))[2:].zfill(len(flag)*4)
ret = ""
k = keystream(key)
for i in flag:
	ret += str(next(k)^int(i))
print(ret)
{% endhighlight %}


It seems that the flag is converted to binary and encrypted with the keystream function seeded by the key defined above. The flag is XORed against the output of the keystream. One obvious way to circumvent the keystream would be to pick our a, b, and c so that the stream always returns zero. XORing with zero has no affect (as seen below). You can read more about the basic properties of XOR [here](https://en.wikipedia.org/wiki/Exclusive_or).

$$0 \oplus 0 = 0 \\ 1 \oplus 0 = 1$$

Looking at the code for the keystream, it immediately becomes apparent that it will often return zero. The key is raised to a random power between 100 and 200. If the key is less than one this will generate an extremely small number. After this it is multiplied by a random power of two between one and 100, but this is far less significant than the previous exponentiation. 

Putting this all together, we can pick values for a, b, and c that fit the requirements outlined earlier. As seen below, a=1 b=3 c=1 will fit the requirements.

```
>>> from decimal import *
>>> a, b, c = 1, 3, 1
>>> key = (Decimal(b*b-4*a*c).sqrt() - Decimal(b))/Decimal(a*2)
>>> key
Decimal('-0.38196601125...') # magnitude less than one and irrational
```

Trying this in the challenge server gives the following...

```
michael@computer:~/Documents$ nc crypto.2020.chall.actf.co 20601
a: 1
b: 3
c: 1
01100001011000110111010001100110011110110110010001101111011101110110111001011111011101000110111101011111011101000110100001100101010111110110010001100101011000110110100101101101011000010110110001111101
```

Since the flag has most likely only been XORed with zero (as determined above), we should be able to simply convert the binary to ascii to get the flag.

```
michael@computer:~/Documents$ python3
Python 3.6.9 (default, Nov  7 2019, 10:44:02) 
[GCC 8.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from Crypto.Util.number import long_to_bytes
>>> flag = int('01100001011000110111010001100110011110110110010001101111011101110110111001011111011101000110111101011111011101000110100001100101010111110110010001100101011000110110100101101101011000010110110001111101', 2)
>>> long_to_bytes(flag).decode()
'actf{down_to_the_decimal}'
```

As we can see the flag is `actf{down_to_the_decimal}`.