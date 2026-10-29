//nolint:testpackage // Differential oracle covers the private Windows device grammar, including superscript digits.
package archiveutil

import (
	"regexp"
	"testing"
)

func FuzzReservedDevice(f *testing.F) {
	old := regexp.MustCompile(`^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[1-9¹²³])$`)
	for _, s := range []string{"", "CON", "CONIN$", "CONOUT$", "COM0", "COM1", "COM¹", "LPT²", "LPT³", "LPT⁴", "COM11", "CON\n", "com1", "\xff"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := reservedDevice(s), old.MatchString(s); got != want {
			t.Fatalf("%q: got %v want %v", s, got, want)
		}
	})
}
