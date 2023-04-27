# Cyclone's Reverb Nation Hash Cracker
Multithreaded hash cracker for Reverb Nation's algo: sha1(eMinor--$saltsha1(eMinor--$plaintext--})--})

Usage:
- ./reverbnation_cracker.bin -w wordlist.txt -h hashes.txt
- version 0.2.1; added sanity checks, buffio and program stats

# Cyclone's Reverb Nation Hash Gen
Hash gen for Reverb Nation's algo: sha1(eMinor--$saltsha1(eMinor--$plaintext--})--})

Usage:
- ./reverbnation_generator.bin (prompts for password)
- version 0.1.0; initial release
