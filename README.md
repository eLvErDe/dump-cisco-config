# Usage

```
usage: dump-cisco-config.py [-h] --filename /tmp/config.txt [--silent]
                            [--enable-password enable_password]
                            192.168.0.1 {ssh,serial:9600} root password
                            {dump,load}
```

Run non interactive script to dump configuration from a network equipement

Positional arguments:
 * `192.168.0.1`           Address of the target equipement
 * `{ssh,serial:9600}`     Protocol to use for connectiong
 * `root`                  Username
 * `password`              Root
 * `{dump,load}`           Dump or load

Optional arguments:
 * `-h`, `--help`  
   show this help message and exit
 * `--filename /tmp/config.txt`  
   filename to use as input or output (default: None)
 * `--silent`  
   Do not echo-output (default: False)
 * `--enable-password enable_password`  
   Enable password (fallback to password if unset (default: None)

# TODO

Serial support looks kinda broken as well as load support but it definitely needs extensive testing.
Dump through SSH on CISCO IOS and ASA is production ready.
