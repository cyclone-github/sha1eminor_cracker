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
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Cyclone's SHA1eMinor Hash Cracker
// POC hash cracker for the custom algo sha1(eMinor--$saltsha1(eMinor--$plaintext--})--})
// coded by cyclone
// multithreaded version
// v2023-09-29.1100; fixed bug that caused program to not exit when all hashes were cracked, multiple code modifications for better hashrate and thread-safety

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

// thread-safe set data structure
type HashSet struct {
	m  map[string]string // store hash as key and salt as value
	mu sync.Mutex
}

// insert new element into set
func (s *HashSet) Add(hash, salt string) {
	s.mu.Lock()
	s.m[hash] = salt
	s.mu.Unlock()
}

// delete element from set
func (s *HashSet) Remove(hash string) {
	s.mu.Lock()
	delete(s.m, hash)
	s.mu.Unlock()
}

// return number of elements in set
func (s *HashSet) Length() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// verify sha1eminor hashes
func verifyCustomSha1(plaintext, salt, expectedHash string) bool {
	innerHash := sha1.Sum([]byte("eMinor--" + plaintext + "--}"))
	computedHash := sha1.Sum([]byte("eMinor--" + salt + hex.EncodeToString(innerHash[:]) + "--}"))
	return hex.EncodeToString(computedHash[:]) == expectedHash
}

// printStats
func printStats(elapsedTime time.Duration, crackedCount int, totalHashes int, linesProcessed int) {
	hours := int(elapsedTime.Hours())
	minutes := int(elapsedTime.Minutes()) % 60
	seconds := int(elapsedTime.Seconds()) % 60
	fmt.Fprintf(os.Stderr, "\nTotal runtime: %02dh:%02dm:%02ds\n", hours, minutes, seconds)
	fmt.Fprintf(os.Stderr, "Hashes cracked: %d / %d\n", crackedCount, totalHashes)
	linesPerSecond := float64(linesProcessed) / elapsedTime.Seconds()
	fmt.Fprintf(os.Stderr, "Lines processed per second: %.2f\n", linesPerSecond)
}

func main() {
	// parse cli
	wordlistFileFlag := flag.String("w", "", "Wordlist file")
	hashFileFlag := flag.String("h", "", "Hash file")
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
		fmt.Fprintln(os.Stderr, string(codedByDecoded))
		os.Exit(0)
	}

	if *versionFlag {
		fmt.Fprintln(os.Stderr, "v2023-09-29.1100")
		os.Exit(0)
	}

	if *wordlistFileFlag == "" || *hashFileFlag == "" {
		fmt.Fprintln(os.Stderr, "Both -w and -h flags are required.")
		os.Exit(1)
	}

	startTime := time.Now()

	// read all hashes into HashSet map
	uncrackedHashes := &HashSet{m: make(map[string]string)}
	hashFile, err := os.Open(*hashFileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error opening hash file:", err)
		os.Exit(1)
	}
	defer hashFile.Close()
	hashScanner := bufio.NewScanner(hashFile)
	for hashScanner.Scan() {
		parts := strings.Split(hashScanner.Text(), ":")
		if len(parts) == 2 {
			uncrackedHashes.Add(parts[0], parts[1])
		}
	}
	totalHashes := uncrackedHashes.Length()

	// variables
	crackedCount := 0
	var crackedCountMu sync.Mutex
	linesPerThread := 100 // number of wordlist lines each thread will read at once
	linesProcessed := 0
	var linesProcessedMu sync.Mutex
	var wg sync.WaitGroup
	var mapMu sync.Mutex            // mutex for synchronizing map access
	var readMu sync.Mutex           // mutex for synchronizing wordlist reading
	stopChan := make(chan struct{}) // signal all hashes have been cracked

	// open wordlist and handle errors
	wordlistFile, err := os.Open(*wordlistFileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error opening wordlist file:", err)
		os.Exit(1)
	}
	defer wordlistFile.Close()
	wordlistReader := bufio.NewReader(wordlistFile)

	// welcome screen
	fmt.Fprintln(os.Stderr, " ----------------------------------- ")
	fmt.Fprintln(os.Stderr, "| Cyclone's SHA1eMinor Hash Cracker |")
	fmt.Fprintln(os.Stderr, " ----------------------------------- ")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Hash file:\t", *hashFileFlag)
	fmt.Fprintln(os.Stderr, "Total Hashes:\t", totalHashes)
	fmt.Fprintln(os.Stderr, "CPU Threads:\t", runtime.NumCPU())
	fmt.Fprintln(os.Stderr, "Wordlist:\t", *wordlistFileFlag)
	fmt.Fprintln(os.Stderr, "Working...\n")

	// handle Ctrl+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		close(stopChan)
	}()

	// start goroutines workers
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopChan:
					// stop if no hashes are left to crack
					return
				default:
					// otherwise, proceed
				}

				words := make([]string, 0, linesPerThread)

				readMu.Lock()
				for j := 0; j < linesPerThread; j++ {
					word, err := wordlistReader.ReadString('\n')
					if err == io.EOF {
						break
					}
					//words = append(words, strings.TrimSpace(word)) // trim whitespace -- isn't safe for plaintext that contain spaces
					words = append(words, strings.TrimRight(word, "\n")) // trim newline
					linesProcessedMu.Lock()
					linesProcessed++
					linesProcessedMu.Unlock()
				}
				readMu.Unlock()

				if len(words) == 0 {
					return
				}

				mapMu.Lock() // lock map
				for _, word := range words {
					for hash, salt := range uncrackedHashes.m {
						if verifyCustomSha1(word, salt, hash) {
							fmt.Printf("%s:%s:%s\n", hash, salt, word)
							uncrackedHashes.Remove(hash)
							crackedCountMu.Lock()
							crackedCount++
							crackedCountMu.Unlock()
							if uncrackedHashes.Length() == 0 {
								close(stopChan) // close stop channel to signal all goroutines to stop
								mapMu.Unlock()
								return
							}
						}
					}
				}
				mapMu.Unlock() // unlock map
			}
		}()
	}

	// wait for all workers to finish
	wg.Wait()

	// print stats
	elapsedTime := time.Since(startTime)
	printStats(elapsedTime, crackedCount, totalHashes, linesProcessed)
}

// end code