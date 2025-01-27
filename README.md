# kcrypt3
kcrypt3 - an experimental cryptosystem based on the NP-hard polynomial
reconstruction problem. Released to the public domain by Kamila
Szewczyk - see COPYING.

Project homepage: https://github.com/kspalaiologos/kcrypt3

## Building

```
# If using a git clone (not needed for source packages), first...
$ ./bootstrap

# All...
$ ./configure
$ make
$ sudo make install
```

## Disclaimer

You know what they say about rolling your own crypto. I find the idea
of novel cryptographic systems interesting and I enjoy tinkering with it,
but there is no guarantee that this program is even remotely secure.
In fact it is likely that it is not, due to the fact that it has not been
independently reviewed for problems as mundane as unintended code bugs, let
alone issues with the code idea or specification.

Even if this program and the underlying idea was secure, it is extremely
slow. Encoding and decoding are performed, on my machine, at the rate of
about 500KiB/s.
