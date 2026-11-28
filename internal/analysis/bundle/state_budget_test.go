package bundle //nolint:testpackage // Inert private state checks resource admission without captured input or detector scenarios.

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/report"
)

func ordinaryBundleState(size int) map[string]bundleValue {
	env := map[string]bundleValue{}
	for i := range size {
		env[fmt.Sprintf("local_%d", i)] = bundleValue{text: "before", known: true}
	}
	return env
}

func TestBundleStateTraversalUsesQuota(t *testing.T) {
	for _, kind := range []string{nodeScope, nodeBranch} {
		for _, quota := range []uint64{1, 4096} {
			t.Run(kind+"/"+strconv.FormatUint(quota, 10), func(t *testing.T) {
				env := ordinaryBundleState(64)
				b := &bundleAnalysis{ctx: analysisbudget.WithLimit(t.Context(), quota)}
				b.eval(&bundleProgram{}, &bundleNode{kind: kind}, env, 0)
				if quota == 1 {
					if b.err == nil || !analysisbudget.Exhausted(b.ctx) {
						t.Fatalf("state traversal escaped quota: used=%d error=%v", analysisbudget.Used(b.ctx), b.err)
					}
				} else if b.err != nil || b.gap != nil || analysisbudget.Used(b.ctx) < uint64(2*len(env)) {
					t.Fatalf("copy and join must visit each name: used=%d error=%v gap=%v", analysisbudget.Used(b.ctx), b.err, b.gap)
				}
				assertOrdinaryBundleState(t, env)
			})
		}
	}
}

func assertOrdinaryBundleState(t *testing.T, env map[string]bundleValue) {
	t.Helper()
	if len(env) != 64 {
		t.Fatalf("namespace changed size: %d", len(env))
	}
	for name, value := range env {
		if !value.known || value.text != "before" {
			t.Fatalf("namespace entry %q changed: %+v", name, value)
		}
	}
}

func TestBundleStatePublicationIsAtomic(t *testing.T) {
	for _, kind := range []string{nodeScope, nodeBranch} {
		t.Run(kind, func(t *testing.T) {
			node := &bundleNode{kind: kind, children: []*bundleNode{{kind: nodeAssign, name: "local_0", children: []*bundleNode{{kind: nodeLiteral, text: "after", known: true}}}}}
			healthy := &bundleAnalysis{ctx: analysisbudget.WithLimit(t.Context(), 4096)}
			env := ordinaryBundleState(64)
			healthy.eval(&bundleProgram{}, node, env, 0)
			if healthy.err != nil || healthy.gap != nil {
				t.Fatalf("healthy state traversal failed: %v / %v", healthy.err, healthy.gap)
			}
			if kind == nodeScope && (!env["local_0"].known || env["local_0"].text != "after") || kind == nodeBranch && env["local_0"].known {
				t.Fatal("healthy scope/branch result changed")
			}
			used := analysisbudget.Used(healthy.ctx)
			for quota := uint64(0); quota <= used; quota++ {
				env := ordinaryBundleState(64)
				b := &bundleAnalysis{ctx: analysisbudget.WithLimit(t.Context(), quota), results: map[string]map[string]result{"ordinary": {}}, limit: 4}
				b.emit("ordinary", report.SourceRef{Path: "retained", ByteStart: 1, ByteEnd: 2})
				b.eval(&bundleProgram{}, node, env, 0)
				if quota < used {
					if b.err == nil || !analysisbudget.Exhausted(b.ctx) {
						t.Fatalf("quota %d failed to stop traversal costing %d", quota, used)
					}
					assertOrdinaryBundleState(t, env)
				} else if b.err != nil || analysisbudget.Exhausted(b.ctx) {
					t.Fatal("exact successful quota was rejected")
				}
				prior := b.results["ordinary"]["retained"]
				if len(prior.Matches) != 1 || prior.Matches[0].Start != 1 || prior.Matches[0].End != 2 {
					t.Fatal("failed state traversal lost previously retained work")
				}
			}
		})
	}
}

func TestBundleEmptyStateAndShadowStayIsolated(t *testing.T) {
	for _, kind := range []string{nodeScope, nodeBranch} {
		b := &bundleAnalysis{ctx: analysisbudget.WithLimit(t.Context(), 2)}
		env := ordinaryBundleState(0)
		b.eval(&bundleProgram{}, &bundleNode{kind: kind}, env, 0)
		if b.err != nil || len(env) != 0 {
			t.Fatal("empty traversal failed or exported an internal marker")
		}
	}
	env := ordinaryBundleState(64)
	b := &bundleAnalysis{ctx: analysisbudget.WithLimit(t.Context(), 4096)}
	node := &bundleNode{kind: nodeScope, locals: map[string]bool{"local_0": true}, children: []*bundleNode{{kind: nodeAssign, name: "local_0", children: []*bundleNode{{kind: nodeLiteral, text: "after", known: true}}}}}
	b.eval(&bundleProgram{}, node, env, 0)
	if b.err != nil {
		t.Fatal(b.err)
	}
	assertOrdinaryBundleState(t, env)
}

type bundleCancelContext struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (ctx *bundleCancelContext) Err() error {
	ctx.checks--
	if ctx.checks == 0 {
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func TestBundleStateCancellationAndReuse(t *testing.T) {
	for _, kind := range []string{nodeScope, nodeBranch} {
		for _, checks := range []int{8, 80} {
			env := ordinaryBundleState(64)
			ctx, cancel := context.WithCancel(t.Context())
			b := &bundleAnalysis{ctx: &bundleCancelContext{Context: ctx, cancel: cancel, checks: checks}}
			node := &bundleNode{kind: kind}
			b.eval(&bundleProgram{}, node, env, 0)
			cancel()
			if b.err == nil || analysisbudget.Exhausted(b.ctx) {
				t.Fatal("copy ignored cancellation or confused it with quota exhaustion")
			}
			assertOrdinaryBundleState(t, env)
			retry := &bundleAnalysis{ctx: analysisbudget.WithLimit(t.Context(), 4096)}
			retry.eval(&bundleProgram{}, node, env, 0)
			if retry.err != nil {
				t.Fatal("cancelled traversal poisoned independent reuse")
			}
			assertOrdinaryBundleState(t, env)
		}
	}
}

func TestBundleCallChargesLocalBindings(t *testing.T) {
	for _, kind := range []string{"locals", "parameters"} {
		for _, quota := range []uint64{1, 4096} {
			t.Run(kind+"/"+strconv.FormatUint(quota, 10), func(t *testing.T) {
				program := &bundleProgram{initialized: true, globals: map[string]bundleValue{}}
				fn := &bundleFunction{program: program, locals: map[string]bool{}}
				for name := range ordinaryBundleState(64) {
					if kind == "locals" {
						fn.locals[name] = true
					} else {
						fn.params = append(fn.params, name)
					}
				}
				b := &bundleAnalysis{ctx: analysisbudget.WithLimit(t.Context(), quota), active: map[*bundleFunction]struct{}{}}
				b.callFunction(fn, nil, 0)
				if quota == 1 {
					if b.err == nil || !analysisbudget.Exhausted(b.ctx) {
						t.Fatal("call bound its private namespace outside quota")
					}
				} else if b.err != nil || analysisbudget.Used(b.ctx) < 64 {
					t.Fatal("healthy binding failed or did not charge the visited names")
				}
				if len(program.globals) != 0 || len(b.active) != 0 {
					t.Fatal("call published partial bindings or leaked a frame")
				}
			})
		}
	}
}

func TestBundleCallAndProjectionCopiesUseQuota(t *testing.T) {
	for _, quota := range []uint64{2, 4096} {
		t.Run("call/"+strconv.FormatUint(quota, 10), func(t *testing.T) {
			program := &bundleProgram{initialized: true, globals: ordinaryBundleState(64)}
			fn := &bundleFunction{program: program, body: []*bundleNode{{kind: nodeReturn, children: []*bundleNode{{kind: nodeName, name: "local_0"}}}}}
			b := &bundleAnalysis{ctx: analysisbudget.WithLimit(t.Context(), quota), active: map[*bundleFunction]struct{}{}}
			value := b.callFunction(fn, nil, 0)
			if quota == 2 {
				if b.err == nil || !analysisbudget.Exhausted(b.ctx) || value.known {
					t.Fatal("call copied globals outside its quota")
				}
			} else if b.err != nil || !value.known || value.text != "before" || analysisbudget.Used(b.ctx) < 64 {
				t.Fatal("healthy call changed its result or failed to charge the copied globals")
			}
			if len(b.active) != 0 {
				t.Fatal("call leaked an active frame")
			}
			assertOrdinaryBundleState(t, program.globals)
		})
		t.Run("projection/"+strconv.FormatUint(quota, 10), func(t *testing.T) {
			locals := map[string]bool{}
			for name := range ordinaryBundleState(64) {
				locals[name] = true
			}
			write := &bundleNode{kind: nodeAssign, name: "outside"}
			b := &bundleAnalysis{ctx: analysisbudget.WithLimit(t.Context(), quota)}
			b.scriptGlobalWrites([]*bundleNode{{kind: nodeScope, children: []*bundleNode{write}}}, locals, 0)
			if quota == 2 {
				if b.err == nil || !analysisbudget.Exhausted(b.ctx) || write.globalWrite {
					t.Fatal("projection copied locals and published a write outside its quota")
				}
			} else if b.err != nil || !write.globalWrite || analysisbudget.Used(b.ctx) < 64 {
				t.Fatal("healthy projection changed its result or failed to charge local copies")
			}
		})
	}
}

func TestBundleStateLocalCeilingIsAtomic(t *testing.T) {
	for _, kind := range []string{nodeScope, nodeBranch} {
		t.Run(kind, func(t *testing.T) {
			node := &bundleNode{kind: kind, children: []*bundleNode{{kind: nodeAssign, name: "local_0", children: []*bundleNode{{kind: nodeLiteral, text: "after", known: true}}}}}
			healthy := &bundleAnalysis{ctx: t.Context()}
			healthy.eval(&bundleProgram{}, node, ordinaryBundleState(64), 0)
			if healthy.err != nil || healthy.operations < 128 {
				t.Fatal("healthy traversal did not admit both namespace visits")
			}
			for _, remaining := range []int{1, healthy.operations - 1, healthy.operations} {
				env := ordinaryBundleState(64)
				b := &bundleAnalysis{ctx: analysisbudget.WithLimit(t.Context(), 4096), operations: 100000 - remaining}
				b.eval(&bundleProgram{}, node, env, 0)
				if remaining < healthy.operations {
					if b.err == nil || analysisbudget.Exhausted(b.ctx) {
						t.Fatal("local ceiling was ignored or confused with the shared quota")
					}
					assertOrdinaryBundleState(t, env)
				} else if b.err != nil || b.operations != 100000 {
					t.Fatal("exact local ceiling was rejected")
				}
			}
		})
	}
}
