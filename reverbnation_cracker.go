package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// POC hash cracker for the custom algo sha1(eMinor--$saltsha1(eMinor--$plaintext--})--}) used by reverb nation
// coded by cyclone
// multithreaded version
// version 0.1.0; initial release
// version 0.2.0; added multithreading support
// version 0.2.1; added sanity checks, buffio and program stats

// clear screen function
func clearScreen() {
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	case "darwin":
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

type HashSet struct {
	m  map[string]bool
	mu sync.Mutex
}

func (s *HashSet) Add(hash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[hash] = true
}

func (s *HashSet) Contains(hash string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.m[hash]
	return ok
}

func main() {
	wordlistFile := flag.String("w", "", "Wordlist file")
	hashFile := flag.String("h", "", "Hash file")
	cycloneFlag := flag.Bool("cyclone", false, "")
	versionFlag := flag.Bool("version", false, "Version number")
	helpFlag := flag.Bool("help", false, "Program usage instructions")
	flag.Parse()

	clearScreen()

	if *helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	if *cycloneFlag {
		codedBy := "Q29kZWQgYnkgY3ljbG9uZSA7KQo="
		codedByDecoded, _ := base64.StdEncoding.DecodeString(codedBy)
		fmt.Println(string(codedByDecoded))
		os.Exit(0)
	}

	if *versionFlag {
		version := "Q3ljbG9uZSBSZXZlcmIgTmF0aW9uIENyYWNrZXIgdjAuMi4xCg=="
		versionDecoded, _ := base64.StdEncoding.DecodeString(version)
		fmt.Println(string(versionDecoded))
		os.Exit(0)
	}

	if *wordlistFile == "" || *hashFile == "" {
		fmt.Println("Both -w and -h flags are required.")
		os.Exit(1)
	}

	wordlist, err := os.Open(*wordlistFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error opening wordlist file:", err)
		os.Exit(1)
	}
	defer wordlist.Close()

	hashes, err := os.Open(*hashFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error opening hash file:", err)
		os.Exit(1)
	}
	defer hashes.Close()

	totalHashes := 0
	hashReader := bufio.NewReader(hashes)
	for {
		hashLine, err := hashReader.ReadString('\n')
		if err == io.EOF {
			if len(strings.TrimSpace(hashLine)) > 0 {
				totalHashes++
			}
			break
		} else if err != nil {
			fmt.Fprintln(os.Stderr, "Error reading hash file:", err)
			os.Exit(1)
		}

		totalHashes++
	}

	writer := bufio.NewWriterSize(os.Stdout, 1*1024*1024)

	numThreads := runtime.NumCPU() * 10

	fmt.Fprintln(os.Stderr, " -------------------------------------- ")
	fmt.Fprintln(os.Stderr, "| Cyclone's Reverb Nation Hash Cracker |")
	fmt.Fprintln(os.Stderr, " -------------------------------------- ")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Hash file:\t", *hashFile)
	fmt.Fprintln(os.Stderr, "Hashes:\t\t", totalHashes)
	//fmt.Fprintln(os.Stderr, "CPU Threads:\t", numThreads)
	fmt.Fprintln(os.Stderr, "Wordlist:\t", *wordlistFile)
	fmt.Fprintln(os.Stderr, "Working...\n")

	wg := &sync.WaitGroup{}
	wg.Add(numThreads)

	// create shared hash map
	crackedHashes := &HashSet{m: make(map[string]bool)}

	startTime := time.Now()

	for i := 0; i < numThreads; i++ {
		scanner := bufio.NewScanner(wordlist)

		go func() {
			defer wg.Done()

			for scanner.Scan() {
				word := strings.TrimSpace(scanner.Text())

				hashes, err := os.Open(*hashFile)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error opening hash file:", err)
					os.Exit(1)
				}

				hashReader := bufio.NewReaderSize(hashes, 1*1024*1024)

				for {
					hashLine, err := hashReader.ReadString('\n')
					if err == io.EOF {
						break
					} else if err != nil {
						fmt.Fprintln(os.Stderr, "Error reading hash file:", err)
						os.Exit(1)
					}

					hashParts := strings.Split(strings.TrimSpace(hashLine), ":")
					if len(hashParts) != 2 {
						continue
					}

					hash, salt := hashParts[0], hashParts[1]

					if crackedHashes.Contains(hash) {
						continue // skip hash if it's already cracked
					}

					if verifyCustomSha1(word, salt, hash) {
						fmt.Fprint(writer, hash, ":", salt, ":", word, "\n")
						writer.Flush()

						// add cracked hash to shared hash map
						crackedHashes.Add(hash)

						break
					}
				}
				hashes.Close()
			}

		}()
	}

	wg.Wait()

	elapsedTime := time.Since(startTime)

	//totalWordlistLines := 0
	wordlistReader := bufio.NewReaderSize(wordlist, 10*1024*1024)
	for {
		_, err := wordlistReader.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Fprintln(os.Stderr, "Error reading wordlist file:", err)
			os.Exit(1)
		}

		//totalWordlistLines++
	}

	totalHashesProcessed := totalHashes
	hashesCracked := len(crackedHashes.m)
	//totalWordsProcessed := totalWordlistLines * numThreads
	//linesPerSecond := float64(totalWordsProcessed) / elapsedTime.Seconds()

	fmt.Fprintln(os.Stderr, "\nTotal runtime:\t", elapsedTime)
	fmt.Fprintln(os.Stderr, "Hashes cracked:", hashesCracked, "/", totalHashesProcessed)
	//fmt.Fprintln(os.Stderr, "Total words processed:", totalWordsProcessed)
	//fmt.Fprintln(os.Stderr, "Lines per second processed:", linesPerSecond)
}

// hacky way to implement reverb nation's custom sha1 algorithm
func verifyCustomSha1(plaintext, salt, expectedHash string) bool {
	innerHash := sha1.Sum([]byte("eMinor--" + plaintext + "--}"))
	computedHash := sha1.Sum([]byte("eMinor--" + salt + hex.EncodeToString(innerHash[:]) + "--}"))
	return hex.EncodeToString(computedHash[:]) == expectedHash
}

// end code
