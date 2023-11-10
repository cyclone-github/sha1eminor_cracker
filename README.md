# SHA1eMinor Hash Cracker
Multithreaded hash cracker for custom algo: sha1(eMinor--$saltsha1(eMinor--$plaintext--})--})

_**This tool was proudly the first publicly released cracker for this custom algo.**_

Usage:

`./sha1eminor_cracker.bin -w wordlist.txt -h hashes.txt`
- v2023-09-29.1100; fixed bug that caused program to not exit when all hashes were cracked, multiple code modifications for better hashrate and thread-safety

# SHA1eMinor Hash Gen
Hash gen for custom algo: sha1(eMinor--$saltsha1(eMinor--$plaintext--})--})

Usage:

`./sha1eminor_generator.bin (prompts for password)`
- v2023-09-29.1100; initial release

### Compile from source code info:
- https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt
