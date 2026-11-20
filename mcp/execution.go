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

const (
	fieldTarget     = "target"
	fieldUploadData = "data_base64"
)

func (s *Server) compare(ctx context.Context, raw json.RawMessage) (report.PreparedDocument, error) {
	var a struct {
		Previous  string `json:"previous"`
		Candidate string `json:"candidate"`
	}
	if strictParams(raw, &a, "previous", "candidate") != nil {
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
	// Field presence distinguishes an omitted upload from an explicit zero-byte upload.
	var args map[string]*string
	if strictParams(raw, &args, fieldTarget, fieldName, fieldUploadData) != nil {
		return report.PreparedDocument{}, errors.New("invalid arguments")
	}

	target, err := s.authorizedInput(args)
	if err != nil {
		return report.PreparedDocument{}, err
	}

	run, err := s.scanner.Scan(ctx, target)

	return s.evaluated(run, err)
}

func (s *Server) authorizedInput(args map[string]*string) (scout.Target, error) {
	if target, provided := args[fieldTarget]; provided {
		if target == nil || len(args) != 1 {
			return scout.Target{}, errors.New("exclusive inputs")
		}

		p, ok := s.options.Targets[*target]
		if !ok {
			return scout.Target{}, errors.New("unauthorized target")
		}

		return scout.Path(p), nil
	}

	name, encoded := args[fieldName], args[fieldUploadData]
	if name == nil || *name == "" || encoded == nil || len(*encoded) > base64.StdEncoding.EncodedLen(MaxUploadBytes) {
		return scout.Target{}, errors.New("upload requires name and bounded data")
	}

	data, err := base64.StdEncoding.Strict().DecodeString(*encoded)
	if err != nil || len(data) > MaxUploadBytes {
		return scout.Target{}, errors.New("invalid upload")
	}

	return scout.Reader(*name, bytes.NewReader(data)), nil
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
