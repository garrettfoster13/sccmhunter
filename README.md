# sccmhunter

```
usage: sccmhunter.py [-h] [-u U] [-p P] [-d D] [-dc-ip DC_IP] [-t T] [-ldaps] [-k] [-no-pass]
                     [-hashes LMHASH:NTHASH] [-aes hex key]

Tool to enumerate a target environment for SCCM Servers.

options:
  -h, --help            show this help message and exit
  -u U                  Username
  -p P                  Password
  -d D                  Domain Name
  -dc-ip DC_IP          IP address or FQDN of domain controller
  -t T                  Target domain to search.
  -ldaps                Use LDAPS instead of LDAP
  -k, --kerberos        Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME)
                        based on target parameters. If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -no-pass              Don't ask for password. (Useful for -k
  -hashes LMHASH:NTHASH
                        LM and NT hashes, format is LMHASH:NTHASH
  -aes hex key          AES key to use for Kerberos Authentication (128 or 256 bits)
```
