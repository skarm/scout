package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/report"
)

type scanArguments struct {
	Target string `json:"target,omitempty"`
	Name   string `json:"name,omitempty"`
	Data   string `json:"data_base64,omitempty"`
}

func (s *Server) compare(ctx context.Context, raw json.RawMessage) (report.PreparedDocument, error) {
	var a struct {
		Previous  string `json:"previous"`
		Candidate string `json:"candidate"`
	}
	if strictParams(raw, &a) != nil {
		return report.PreparedDocument{}, errors.New("invalid arguments")
	}

	p, ok := s.options.Targets[a.Previous]
	z, yes := s.options.Targets[a.Candidate]

	if !ok || !yes {
		return report.PreparedDocument{}, errors.New("unauthorized target")
	}

	return s.evaluated(s.scanner.Compare(ctx, scout.Path(p), scout.Path(z), scout.DefaultCompareOptions()))
}

func (s *Server) scan(ctx context.Context, raw json.RawMessage) (report.PreparedDocument, error) {
	var a scanArguments
	if strictParams(raw, &a) != nil {
		return report.PreparedDocument{}, errors.New("invalid arguments")
	}

	target, err := s.authorizedInput(a)
	if err != nil {
		return report.PreparedDocument{}, err
	}

	run, err := s.scanner.Scan(ctx, target)

	return s.evaluated(run, err)
}

func (s *Server) authorizedInput(a scanArguments) (scout.Target, error) {
	if a.Target != "" {
		if a.Name != "" || a.Data != "" {
			return scout.Target{}, errors.New("exclusive inputs")
		}

		p, ok := s.options.Targets[a.Target]
		if !ok {
			return scout.Target{}, errors.New("unauthorized target")
		}

		return scout.Path(p), nil
	}

	if a.Name == "" || len(a.Data) > base64.StdEncoding.EncodedLen(MaxUploadBytes) {
		return scout.Target{}, errors.New("upload requires name and bounded data")
	}

	data, err := base64.StdEncoding.Strict().DecodeString(a.Data)
	if err != nil || len(data) > MaxUploadBytes {
		return scout.Target{}, errors.New("invalid upload")
	}

	return scout.Reader(a.Name, bytes.NewReader(data)), nil
}

func (s *Server) evaluated(run report.Run, scanErr error) (report.PreparedDocument, error) {
	if run.State == report.Unknown {
		if scanErr == nil {
			scanErr = errors.New("inspection produced no result")
		}

		return report.PreparedDocument{}, scanErr
	}

	if scanErr != nil && run.State == report.RunComplete {
		return report.PreparedDocument{}, errors.New("inspection result is inconsistent")
	}

	return report.Prepare(report.NewDocument(run, s.gate.Evaluate(run, time.Now())))
}
