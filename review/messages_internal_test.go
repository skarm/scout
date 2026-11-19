// Exercises private implementation details and package fixtures.
package review

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"
)

func TestResponseDecodersPreserveExpiredDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	for _, decode := range []func(context.Context, []byte) (Completion, error){decodeChatCompletion, decodeMessagesCompletion} {
		if _, err := decode(ctx, []byte(`{}`)); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("lost response deadline: %v", err)
		}
	}
}

func FuzzAWSRegion(f *testing.F) {
	old := regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+){1,3}-[0-9]$`)
	for _, s := range []string{"", "us-east-1", "eu-central-9", "us-iso-east-1", "us-isob-east-1", "us-a-b-c-1", "us-a-b-c-d-1", "us--1", "us-a-11", "usa-east-1", "us-a-b", "Ks-east-1", "US-east-1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := validAWSRegion(s), old.MatchString(s); got != want {
			t.Fatalf("%q: got %v want %v", s, got, want)
		}
	})
}
