# Cache-timing Attacks on Intel SGX

We present an access-driven cache-timing attack on AES
when running inside an Intel SGX enclave. Using Neve
and Seifert’s elimination method, as well as a cache probing
mechanism relying on Intel PCM, we are able to extract the
AES secret key in less than 10 seconds by investigating 480
encrypted blocks on average. The AES implementation we
attack is based on a Gladman AES implementation taken
from an older version of OpenSSL, which is known to be
vulnerable to cache-timing attacks. In contrast to previous
works on cache-timing attacks, our attack has to be exe-
cuted with root privileges running on the same host as the
vulnerable enclave. Intel SGX, however, was designed to
precisely protect applications against root-level attacks. As
a consequence, we demonstrate that SGX cannot withstand
its designated attacker model when it comes to side-channel
vulnerabilities. To the contrary, the attack surface for side-
channels increases dramatically in the scenario of SGX due to
the power of root-level attackers, for example, by exploiting
the accuracy of PCM, which is restricted to kernel code.

Visit https://www1.cs.fau.de/sgx-timing for more information.

# Requirements

TODO

# Usage

TODO
