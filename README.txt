MD5 in C and x86 assembly
By Odzhan

If you're searching for a highly optimized implementation of MD5, the source
code included here is not suitable since it has been written with instructions
which cannot be executed in parallel on x86 CPU.

The design of how blocks are processed also slows down computation so I would
advise you look at OpenSSL or something entirely different as you may be
disappointed with performance.

What this code does do is reduce the amount of space required but of course.
The code is public domain, feel free to do as you wish with it.

@Odzhan_
2015