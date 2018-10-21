## Notes

* This code is used after x509dump is used. It pairs up certificates and keys (if there were pairs)
* Please run it on Linux or you will have a bad time getting binary dependencies (i.e. OpenSSL, etc..) to work and it's a pain to try to support anyone who might use this on Windows, thx.


## More notes

This is very poorly written and violates all sorts of PEP8 and linting rules but I don't have time to clean it up. I tested it, it works.

## Using

This can run on Linux and requires the output of x509dump in a directory which is specified on the command-line. The out directory (results directory) should also be specified.
