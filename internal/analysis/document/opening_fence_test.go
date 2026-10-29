//nolint:testpackage // Differential oracle compares every opening-fence result, including fields returned with ok=false.
package document

import (
	"regexp"
	"strings"
	"testing"
)

func FuzzOpeningFence(f *testing.F) {
	old := regexp.MustCompile("(?s)^( {0,3})(`{3,}|~{3,})(.*)$")
	for _, s := range []string{"", "```", "~~~", "    ```", "   ```` python", "```python`", "```\nhello", "~~~\u00a0python\u00a0", " \xff```", "\t```", "``~", "~~~```"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		indent, ch, width, info, ok := openingFence(s)
		wi, wc, ww, win, wo := 0, byte(0), 0, "", false
		if match := old.FindStringSubmatch(s); match != nil {
			wi, wc, ww, win = len(match[1]), match[2][0], len(match[2]), strings.TrimSpace(match[3])
			wo = wc != '`' || !strings.ContainsRune(win, '`')
		}
		if indent != wi || ch != wc || width != ww || info != win || ok != wo {
			t.Fatalf("%q: got (%d %c %d %q %v) want (%d %c %d %q %v)", s, indent, ch, width, info, ok, wi, wc, ww, win, wo)
		}
	})
}
