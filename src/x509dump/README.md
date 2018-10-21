## Notes

This code is used initially to dump certificates/keypairs out of running Microsoft Windows Processes. In and of itself it isn't very useful, you will want to use x509helper on the output to match, dedup and validate all findings. This is very poorly written from the era of 2013/2014 and violates all sorts of PEP8 and linting rules but I don't have time to clean it up before publishing

## Code standards and practices

Please do not use this code as a reference, it is very old and poorly written

## Architectures

x86_64 architecture was not widely deployed at the time of original writiting and as such there is no compatibility for x86_64 processes. However, you can use this on x86 processes even when on an x86_64 OS, such as Windows 7 x86_64.

## Using

Run this:

* On Windows only
* With Administrator privileges (you need `SeDebugPrivilege`)

## License

See LICENSE.txt or LICENSE.md in the root of this repository

_Copyright © `2013-2018, `<copyright@mzpqnxow.com>`_  
_All rights reserved._
