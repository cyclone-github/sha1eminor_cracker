package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// hash generator for the custom algo sha1(eMinor--$saltsha1(eMinor--$plaintext--})--})
// coded by cyclone
// version 0.1.0; initial release

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

func main() {
	clearScreen()
	fmt.Fprintln(os.Stderr, " ------------------------------- ")
	fmt.Fprintln(os.Stderr, "| Cyclone's SHA1eMinor Hash Gen |")
	fmt.Fprintln(os.Stderr, " ------------------------------- ")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Enter password to hash: ")
	var password string
	_, err := fmt.Scan(&password)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading input:", err)
		os.Exit(1)
	}

	salt, err := generateRandomSalt(20)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error generating random salt:", err)
		os.Exit(1)
	}

	hashedPassword := createCustomHashedPassword(password, salt)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, hashedPassword+":"+salt)
	fmt.Fprintln(os.Stderr)
}

func createCustomHashedPassword(plaintext, salt string) string {
	innerHash := sha1.Sum([]byte("eMinor--" + plaintext + "--}"))
	computedHash := sha1.Sum([]byte("eMinor--" + salt + hex.EncodeToString(innerHash[:]) + "--}"))
	return hex.EncodeToString(computedHash[:])
}

func generateRandomSalt(length int) (string, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(salt), nil
}

// end code