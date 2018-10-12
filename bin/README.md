first use x509dump.exe to dump keys/certs from a process
then use x509helper2.exe to process all the dumped files and produce a readable report on them

the -o option will automatically create output dirs for you if you want
also with x509dump, you don't have to specify a pid or window, it will give you a menu if you without -p or -w
it will also get full privileges if you run as an administrator (SeDebugPrivileges)

the blacklist.conf blacklists a ton of browser CAs but could use more.

A

