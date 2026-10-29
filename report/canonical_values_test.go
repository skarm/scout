//nolint:testpackage // Tests exercise the private canonical scalar domain.
package report

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestCanonicalValuesPreserveExactLeafEncoding(t *testing.T) {
	text := "<>&\u2028\u2029\x00" + string([]byte{0xff})
	var missing *int
	number := int64(math.MinInt64)
	for _, tc := range []struct {
		value any
		want  string
	}{
		{value: true, want: "true"},
		{value: false, want: "false"},
		{value: -1, want: "-1"},
		{value: int8(-128), want: "-128"},
		{value: int16(-32768), want: "-32768"},
		{value: int32(-2147483648), want: "-2147483648"},
		{value: number, want: "-9223372036854775808"},
		{value: uint(1), want: "1"},
		{value: uint8(255), want: "255"},
		{value: uint16(65535), want: "65535"},
		{value: uint32(4294967295), want: "4294967295"},
		{value: uint64(math.MaxUint64), want: "18446744073709551615"},
		{value: customCanonicalInteger(7), want: "7"},
		{value: text, want: `"\u003c\u003e\u0026\u2028\u2029\u0000�"`},
		{value: missing, want: "null"},
		{value: &missing, want: "null"},
		{value: &number, want: "-9223372036854775808"},
		{value: [2]int{2, 1}, want: "[2,1]"},
		{value: canonicalOmissionValue{}, want: `{"keep":""}`},
		{
			value: canonicalOmissionValue{Empty: "value", Keep: "kept", Mixed: 1, Optional: "present"},
			want:  `{"empty":"value","keep":"kept","mixed":1,"optional":"present"}`,
		},
	} {
		got, err := canonicalValue([]byte("prefix:"), reflect.ValueOf(tc.value), "")
		if err != nil || string(got) != "prefix:"+tc.want {
			t.Fatalf("%T encoded as %s, %v; want %s", tc.value, got, err, tc.want)
		}
	}
}

func TestCanonicalValuesRejectUnsupportedDomain(t *testing.T) {
	for _, value := range []any{float32(1), float64(1), uintptr(1), complex64(1), map[string]int{"x": 1}, make(chan int), func() {}} {
		got, err := canonicalValue([]byte("prefix:"), reflect.ValueOf(value), "")
		if err == nil || !strings.HasPrefix(err.Error(), "unsupported report value ") || got != nil {
			t.Fatalf("unsupported %T encoded as %s, %v", value, got, err)
		}
	}
}

func FuzzCanonicalStringMatchesJSON(f *testing.F) {
	for _, text := range []string{"", "ordinary ASCII", "<>&\u2028\u2029\x00", "Привет🙂", "\xff\xfe", "\"\\\n\t\x01"} {
		f.Add(text)
	}
	f.Fuzz(func(t *testing.T, text string) {
		got, err := canonicalScalar([]byte("prefix:"), reflect.ValueOf(text))
		want, marshalErr := json.Marshal(text)
		if err != nil || marshalErr != nil || !bytes.Equal(got, append([]byte("prefix:"), want...)) {
			t.Fatalf("canonical scalar differs from JSON for %q: %q != %q", text, got, want)
		}
	})
}

type customCanonicalInteger int64

type canonicalOmissionValue struct {
	Empty    string `json:"empty,omitzero"`
	Keep     string `json:"keep"`
	Mixed    int    `json:"mixed,omitempty,omitzero"`
	Optional string `json:"optional,omitempty"`
}

func (customCanonicalInteger) MarshalJSON() ([]byte, error) { return []byte(`"override"`), nil }
