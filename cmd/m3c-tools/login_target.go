package main

import "os"

// loginAPIURL selects nonsecret configuration without invoking credential stores.
func loginAPIURL() string {
	if value := os.Getenv("ER1_API_URL"); value != "" {
		return value
	}
	return "https://127.0.0.1:8081/upload_2"
}
