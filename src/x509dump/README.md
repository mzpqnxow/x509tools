## Notes

This code is used initially to dump certificates/keypairs out of running Microsoft Windows Processes. In and of itself it isn't very useful, you will want to use x509helper on the output to match, dedup and validate all findings. This is very poorly written from the era of 2013/2014 and violates all sorts of PEP8 and linting rules but I don't have time to clean it up before publishing. Sorry for eyebleed.

## Using

This code must run on Microsoft Windows against a live process with Administrator privileges (in order to be granted `SeDebugPrivilege`)

## License

See LICENSE.txt or LICENSE.md in the root of this repository

_Copyright © `2013-2018, `<copyright@mzpqnxow.com>`_  
_All rights reserved._