[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
# x509tools

A (very) old and unmaintained Python project used to dump x509/DER keys and certificates from live Windows processes. This was written around 2011. Maybe it will be useful to someone, it is unmaintained and has not been tested wince Windows 7

## x509dump.py

This tool will dump all certificates and keys from a live/running Win32 process. It isn't terribly smart and relies on known DER and PEM patterns, but it finds a LOT of stuff

## x509helper

This tool will post-process all of the files in the output directory from x509dump.py. It will pair keys with certificates so you can find out if you have just a standard public cert list or if you have some real keys.

## Purpose of Release

As stated, this code is old and unmaintained and at this point untested. It is nothing revolutionary, especially in 2018, and is probably only useful as a reference to anyone wanting to do in memory poking/search of Win32 processes from Python

## Caveats / Warnings

* This has not been tested since Windows 7
* You must be Local Administrator to acquire SeDebugPrivilege privileges on modern versions of Windows
* Though in practice it has not caused any crashes (it is a passive tool and does not write memory) it theoretically could cause a process to crash, so don't use it on anything critical and say I didn't warn you
* It probably won't work on newer versions of Windows with protections against memory inspection for certain processes, though I'm not sure about this

# Credits

All of the cryptography logic is mine, the bindings/wrappers for the Win32 API calls are provided by the (in-tree) win32 library.

# License (covering all except code under win32/)

This work is released under the 3-caluse BSD license (C) copyright@mzpqnxow.com

```
Copyright 2014-2018, copyright@mzpqnxow.com

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
