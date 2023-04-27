# Cyclone's SHA1eMinor Hash Cracker
Multithreaded hash cracker for custom algo: sha1(eMinor--$saltsha1(eMinor--$plaintext--})--})

Usage:
- ./sha1eminor_cracker.bin -w wordlist.txt -h hashes.txt
- version 0.2.1; added sanity checks, buffio and program stats

# Cyclone's SHA1eMinor Hash Gen
Hash gen for custom algo: sha1(eMinor--$saltsha1(eMinor--$plaintext--})--})

Usage:
- ./sha1eminor_generator.bin (prompts for password)
- version 0.1.0; initial release
