// Constructor control for the actual Elephant provider loader, not a menu.
package main

import "os"

func init() {
	path := os.Getenv("SYMBI_PROVIDER_MARKER")
	nonce := os.Getenv("SYMBI_PROVIDER_NONCE")
	if path == "" || nonce == "" {
		panic("missing disposable constructor probe binding")
	}
	if err := os.WriteFile(path, []byte(nonce), 0600); err != nil {
		panic(err)
	}
}

// Returning false avoids registering a provider after its constructor ran.
// The marker demonstrates execution even when no provider is listed.
func Available() bool { return false }

func main() {}
