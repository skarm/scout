// Package scout inspects agent skills and plugins without executing their code.
// Create a Scanner with New and DefaultOptions, then call Close to release its
// native resources.
//
// Scan, ScanMany and Compare return inspection runs. ErrIncomplete may accompany
// a usable run containing partial observations. Preflight errors may return no run.
//
// The policy package evaluates runs using trusted operator settings. The report
// package validates and renders the resulting documents. Finding severity,
// execution completeness and policy decisions are separate results.
package scout
