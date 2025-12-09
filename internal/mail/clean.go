package mail

func CleanString(s string) string {
	out := make([]byte, 0, len(s))
	for _, c := range []byte(s) {
		if c >= 32 && c <= 126 && c != '|' {
			out = append(out, c)
		} else {
			out = append(out, '?')
		}
	}
	return string(out)
}
