package mail

import "testing"

// FuzzCheckMail ensures arbitrary input never panics: a panic inside the
// filter would leave the SMTP transaction without a filter result.
func FuzzCheckMail(f *testing.F) {
	f.Add("From: a@example.com\nContent-Type: multipart/mixed; boundary=\"B\"\n\n--B\nContent-Type: text/plain\n\nhi\n--B--\n")
	f.Add("From: a@example.com\nContent-Type: application/zip; name=\"a.zip\"\nContent-Transfer-Encoding: base64\n\nUEsDBBQAAAAIAA==\n")
	f.Add("From: a@example.com\nContent-Type: application/gzip; name=\"r.xml.gz\"\nContent-Transfer-Encoding: base64\n\nH4sIAAAAAAAA/7Ox0ffxdHZ1C/J19FIAAIBz+3YQAAAA\n")
	f.Add("From: a@example.com\nContent-Type: message/rfc822\n\nFrom: b\nContent-Type: multipart/mixed; boundary=x\n\n--x\n\n--x--\n")
	f.Fuzz(func(t *testing.T, raw string) {
		CheckMail(raw, prodAllowed, 512)
	})
}
