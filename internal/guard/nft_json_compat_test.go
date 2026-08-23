package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExternalNftJSONAllowsUnknownNonCriticalFields(t *testing.T) {
	const table = "wg_mix_ebpf_guard_0123456789abcdef"
	document := []byte(`{
		"nftables": [
			{"metainfo": {
				"json_schema_version": 2,
				"future_metainfo": {"feature": true}
			}},
			{"table": {
				"family": "inet",
				"name": "wg_mix_ebpf_guard_0123456789abcdef",
				"handle": 42,
				"comment": "owner",
				"future_table_metadata": [1, 2, 3]
			}}
		],
		"future_document_metadata": "ignored"
	}`)
	tables, err := parseProjectTableInventoryJSON(document)
	if err != nil {
		t.Fatalf("compatible nft inventory extension was rejected: %v", err)
	}
	if len(tables) != 1 || tables[0] != table {
		t.Fatalf("project tables = %v, want [%s]", tables, table)
	}
	identity, err := parseTableIdentityJSON(document, table)
	if err != nil {
		t.Fatalf("compatible nft table extension was rejected: %v", err)
	}
	if !identity.Exists || identity.Handle != 42 || identity.Comment != "owner" {
		t.Fatalf("unexpected extended table identity: %#v", identity)
	}
}

func TestExternalNftJSONStillRejectsSafetyCriticalDrift(t *testing.T) {
	documents := map[string]string{
		"missing-array":        `{}`,
		"null-array":           `{"nftables": null}`,
		"missing-metainfo":     `{"nftables": []}`,
		"duplicate-metainfo":   `{"nftables": [{"metainfo": {"json_schema_version": 1}}, {"metainfo": {"json_schema_version": 1}}]}`,
		"missing-schema":       `{"nftables": [{"metainfo": {}}]}`,
		"invalid-schema":       `{"nftables": [{"metainfo": {"json_schema_version": 0}}]}`,
		"invalid-family-type":  `{"nftables": [{"metainfo": {"json_schema_version": 1}}, {"table": {"family": 7, "name": "clean"}}]}`,
		"duplicate-root-key":   `{"nftables": [], "nftables": []}`,
		"duplicate-table-key":  `{"nftables": [{"metainfo": {"json_schema_version": 1}}, {"table": {"family": "inet", "family": "ip", "name": "clean"}}]}`,
		"ambiguous-item-shape": `{"nftables": [{"metainfo": {"json_schema_version": 1}, "table": {"family": "inet", "name": "clean"}}]}`,
	}
	for name, document := range documents {
		t.Run(name, func(t *testing.T) {
			if _, err := parseProjectTableInventoryJSON([]byte(document)); err == nil {
				t.Fatalf("unsafe nft inventory drift was accepted: %s", document)
			}
		})
	}
}

func TestOwnerRecordSchemaRemainsStrictWhenNftJSONIsExtended(t *testing.T) {
	stateDir := guardTestStateDir(t)
	executor := CommandExecutor{StateDir: stateDir}
	if _, _, err := executor.loadOrCreateOwner(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(stateDir, OwnerRecordFileName))
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimSpace(string(data))
	if !strings.HasSuffix(trimmed, "}") {
		t.Fatalf("owner record is not a JSON object: %q", data)
	}
	withUnknownField := strings.TrimSuffix(trimmed, "}") + `, "future": true}`
	if err := ValidateOwnerRecordBytes(stateDir, []byte(withUnknownField)); err == nil ||
		!strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("owner record accepted an unknown field: %v", err)
	}
}
