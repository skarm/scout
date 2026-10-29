package signatures_test

import (
	"strings"
	"testing"

	"github.com/skarm/scout/internal/signatures"
)

func TestRansomwareContextExclusions(t *testing.T) {
	for _, tc := range []struct {
		text    string
		negated bool
	}{
		{text: "Never pay the ransom in Bitcoin", negated: true},
		{text: "Do not pay 1 BTC to decrypt your files", negated: true},
		{text: "You should never send BTC to decrypt your files", negated: true},
		{text: "Don't forget to pay 1 BTC to decrypt your files", negated: false},
		{text: "Do not hesitate to pay 1 BTC to decrypt your files", negated: false},
		{text: "Never pay less than 1 BTC to decrypt your files", negated: false},
		{text: "If you don't pay 1 BTC your files will be deleted", negated: false},
	} {
		at := func() []int {
			for _, word := range []string{"pay", "send"} {
				if at := strings.Index(tc.text, word); at >= 0 {
					return []int{at, at + len(word)}
				}
			}
			return nil
		}()
		if at == nil {
			t.Fatal(tc.text)
		}
		if got := signatures.NegatedRansomwarePaymentForTest([]byte(tc.text), at[0]); got != tc.negated {
			t.Errorf("%q: %v", tc.text, got)
		}
	}
}

func TestRansomwareStorageContext(t *testing.T) {
	data := []byte("ransom at rest")
	if signatures.AcceptRansomwareInstanceForTest("$ransom_note", data, 0, 6) {
		t.Fatal("storage context accepted as a ransom note")
	}
	if !signatures.AcceptRansomwareInstanceForTest("$ransom_note", []byte("ransom demand"), 0, 6) {
		t.Fatal("ransom note rejected")
	}
}
