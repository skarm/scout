//nolint:testpackage // Exercises private implementation details and package fixtures.
package maintenance

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"strings"
	"testing"
)

func TestFixedRuntimeInventoryAndCopyPreserveBytesAndRejectLinks(t *testing.T) {
	source, target := t.TempDir(), t.TempDir()
	maintenanceFile(t, source, "pkg/a.py", []byte("inert"))
	maintenanceFile(t, source, "__pycache__/skip.py", []byte("skip"))
	inventory, err := treeInventory(source)
	if err != nil || len(inventory) != 1 || inventory[0].Path != "pkg/a.py" || inventory[0].SHA256 != digest([]byte("inert")) {
		t.Fatalf("bad inventory: %+v %v", inventory, err)
	}
	if err := copyTree(source, target); err != nil {
		t.Fatal(err)
	}
	copied, err := treeInventory(target)
	if err != nil || !reflect.DeepEqual(copied, inventory) {
		t.Fatal("corpus copy changed its byte inventory")
	}
	if err := os.Symlink(filepath.Join(source, "pkg/a.py"), filepath.Join(source, "link.py")); err != nil {
		t.Fatal(err)
	}
	if _, err := treeInventory(source); err == nil {
		t.Fatal("inventory accepted a linked source")
	}
	if err := copyTree(source, t.TempDir()); err == nil {
		t.Fatal("corpus copy accepted a linked source")
	}
}

func TestInstalledOracleInspectionChecksSourceAndDistributionMetadata(t *testing.T) {
	upstream, venv := t.TempDir(), t.TempDir()
	python := filepath.Join(venv, "bin/python")
	maintenanceFile(t, upstream, "src/skillspector/module.py", []byte("pinned source"))
	site := "lib/python3.12/site-packages/"
	maintenanceFile(t, venv, site+"skillspector/module.py", []byte("pinned source"))
	maintenanceFile(t, venv, site+"skillspector-2.12.dist-info/METADATA", []byte("Name: skillspector\nVersion: "+upstreamVersion+"\n"))
	maintenanceFile(t, venv, site+"yara.dist-info/METADATA", []byte("Name: yara-python\nVersion: fixture\n"))
	result, err := inspectInstalledRuntime(python, upstream)
	if err != nil || result.Skillspector != upstreamVersion || result.Yara != "fixture" || len(result.VerifiedFiles) != 1 {
		t.Fatalf("runtime inspection failed: %+v %v", result, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := verifyInstalledRuntime(ctx, python, upstream); err == nil {
		t.Fatal("cancelled oracle version subprocess was accepted")
	}
	maintenanceFile(t, venv, site+"skillspector/module.py", []byte("modified source"))
	if _, err := inspectInstalledRuntime(python, upstream); err == nil {
		t.Fatal("modified installed runtime accepted")
	}
	if metadataField("Name: package\nVersion: 1\n", "Name") != "package" || metadataField("Name: package\n", "Version") != "" {
		t.Fatal("metadata field parsing changed")
	}
}

func TestSandboxPlansRemainExplicitAndCancellationDoesNotRunAnOracle(t *testing.T) {
	environment := cleanEnvironment("/operator/venv/bin/python", "/private/home", "/private/tmp")
	joined := strings.Join(environment, "\n")
	if !strings.Contains(joined, "HOME=/private/home") || !strings.Contains(joined, "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1") || strings.Contains(joined, "PYTHONPATH=") {
		t.Fatal("oracle environment is no longer explicit")
	}
	if !strings.Contains(networkProfile("", false), "(deny network*)") || strings.Contains(networkProfile("", false), "localhost") {
		t.Fatal("network-denied profile weakened")
	}
	if profile := networkProfile(`/tmp/with"quote`, true); !strings.Contains(profile, `with\"quote`) || !strings.Contains(profile, "localhost:*") {
		t.Fatal("loopback profile did not quote its selected root")
	}
	if goruntime.GOOS == "darwin" {
		if err := requireSandbox(); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := runSandboxed(ctx, networkProfile("", false), t.TempDir(), environment, "/not/an/oracle"); err == nil {
		t.Fatal("cancelled oracle command ran")
	}
	if err := checkNetworkDenial(ctx, networkProfile("", false), t.TempDir(), environment); err == nil {
		t.Fatal("cancelled denial probe passed")
	}
	if err := networkDenialProbe(ctx); err == nil {
		t.Fatal("cancellation was mistaken for verified OS network denial")
	}
	output := t.TempDir()
	if _, err := streamUpstreamSuite(ctx, t.TempDir(), output, environment, []string{"--never-execute"}); err == nil {
		t.Fatal("cancelled oracle suite succeeded")
	}
	for _, name := range []string{"stdout.log", "stderr.log"} {
		if info, err := os.Stat(filepath.Join(output, name)); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("cancelled workflow did not retain private logs")
		}
	}
}

func TestRuntimeJSONAndLocalPathContracts(t *testing.T) {
	root := t.TempDir()
	if _, err := safeJoin(root, "../escape"); err == nil {
		t.Fatal("artifact path escaped its root")
	}
	if name, err := safeJoin(root, "a/file"); err != nil || name != filepath.Join(root, "a/file") {
		t.Fatal("local path normalization changed")
	}
	if root, err := projectRoot(); err != nil || root == "" {
		t.Fatal("repository root discovery failed")
	}
	parsed, _ := url.Parse("https://github.com/example/repo")
	_, item, _ := sourceFixture()
	if err := verifyArtifactURL(parsed, strings.Repeat("a", 40), item); err != nil {
		t.Fatal(err)
	}
	if got := obj(map[string]any{"x": true}); !boolean(got["x"]) {
		t.Fatal("JSON object boundary lost a field")
	}
	if obj(object{"x": true}) == nil || obj("not-object") != nil {
		t.Fatal("JSON object shape changed")
	}
}
