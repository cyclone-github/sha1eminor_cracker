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

### Compile from source:
- If you want the latest features, compiling from source is the best option since the release version may run several revisions behind the source code.
- This assumes you have Go and Git installed
  - `git clone https://github.com/cyclone-github/sha1eminor_cracker.git`
  - `cd sha1eminor_cracker`
  - `go mod init sha1eminor_cracker.go`
  - `go mod tidy`
  - `go build -ldflags="-s -w" sha1eminor_cracker.go`
- Compile from source code how-to:
  - https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt
