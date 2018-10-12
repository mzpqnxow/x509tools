# x509tools Binary Distribution, Prepared by [py2exe](http://www.py2exe.org)

The x509tools source code is available, but because they run on Windows and have some dependencies that require building specific versions of OpenSSL (and building and linking Python Cryptography modules against them) a binary package is included here. It is very old (2013-2014) but should work on modern Windows. Make sure you run it as Administrator as it will need `SeDebugPrivilege`

## x509tools - tools for dumping and analyzing PEM and DER certificates/keys in memory (win32)

x509tools is made up of two tools that are meant to be used together

### x509dump.exe 

This tool will take a Microsoft Windows window name and will attach to its process and perform an exhaustive search of memory for PEM and DER formatted keys and certificates. It will write what it finds to individual files in a directory on the filesystem. When using the `-o` option, the tool will automatically create an output directory for you if it does not yet exist. Optionally, specify an existing directory. It doesn't have to be empty, so you can make multiple runs against multiple programs and store all of the certificates and keys in a single directory to collect a large amount, even for a whole system, by iterating over the PIDs outside of the application before executing it. Also, the `-p <pid>` and `-w <window>` flags are optional and a menu will be provided to you to choose from.

### x509helper2.exe

This tool is a post-processing tool, meant to run with the output directory from `x509dump.exe` as its input. It validates the output files. It does the following:

1. Makes sure the file is complete/valid
2. Determines if it is a key or certificate
3. Names the files in a way that that they can be paired with their respective certificate or key, if both a key and certificate were dumped




