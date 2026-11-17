package store

import "strings"

// NormalizeEmail lowercases and trims an email address. Emails are stored and
// looked up in this form, so every path that accepts an email from user input
// must normalize it first.
func NormalizeEmail(email string) string {
	return strings.TrimSpace(strings.ToLower(email))
}
