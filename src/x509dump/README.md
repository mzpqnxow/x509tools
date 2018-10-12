## Notes

This code is used initially to dump certificates/keypairs out of running Microsoft Windows Processes. In and of itself it isn't very useful, you will want to use x509helper on the output to match, dedup and validate all findings.

## More notes

This is very poorly written and violates all sorts of PEP8 and linting rules but I don't have time to clean it up. I tested it, it works.

## Using

This can run on Linux and requires the output of x509dump in a directory which is specified on the command-line. The out directory (results directory) should also be specified.