package guard

import (
	"fmt"
	"strings"
	"testing"
)

type liveGuardChainShape struct {
	Type     string
	Hook     string
	Priority int
	Policy   string
}

func validateLiveGuardTableShapeJSON(
	data []byte,
	owner ownerRecord,
	expectedHandle uint64,
) error {
	if err := owner.validateSelf(); err != nil {
		return fmt.Errorf("validate expected live owner: %w", err)
	}
	if expectedHandle == 0 {
		return fmt.Errorf("expected live table handle must be non-zero")
	}
	items, err := parseNftJSONItems(data)
	if err != nil {
		return fmt.Errorf("parse live guard table JSON: %w", err)
	}
	expectedChains := map[string]liveGuardChainShape{
		"input": {
			Type:     "filter",
			Hook:     "input",
			Priority: -300,
			Policy:   "accept",
		},
		"output": {
			Type:     "filter",
			Hook:     "output",
			Priority: -300,
			Policy:   "accept",
		},
	}
	metainfoCount := 0
	tableCount := 0
	chains := make(map[string]liveGuardChainShape)
	for index, item := range items {
		if len(item) != 1 {
			return fmt.Errorf("live nft item %d has %d object keys, want 1", index, len(item))
		}
		for objectType, raw := range item {
			switch objectType {
			case "metainfo":
				metainfoCount++
				if metainfoCount != 1 {
					return fmt.Errorf("live nft document contains duplicate metainfo")
				}
				if err := validateNftJSONMetainfo(raw); err != nil {
					return err
				}
				continue
			case "table":
				var table struct {
					Family  string   `json:"family"`
					Name    string   `json:"name"`
					Comment string   `json:"comment"`
					Handle  uint64   `json:"handle"`
					Flags   []string `json:"flags"`
				}
				if err := decodeStrictJSON(raw, &table); err != nil {
					return fmt.Errorf("parse live table metadata: %w", err)
				}
				if table.Family != "inet" || table.Name != owner.Table {
					return fmt.Errorf(
						"live table metadata targets %s %s, want inet %s",
						table.Family,
						table.Name,
						owner.Table,
					)
				}
				tableCount++
				if tableCount != 1 {
					return fmt.Errorf("live table metadata is duplicated")
				}
				if table.Comment != owner.Marker || table.Handle != expectedHandle {
					return fmt.Errorf(
						"live table identity marker=%q handle=%d, want marker=%q handle=%d",
						table.Comment,
						table.Handle,
						owner.Marker,
						expectedHandle,
					)
				}
				if len(table.Flags) != 0 {
					return fmt.Errorf("live guard table has unexpected flags %v", table.Flags)
				}
			case "chain":
				var chain struct {
					Family  string   `json:"family"`
					Table   string   `json:"table"`
					Name    string   `json:"name"`
					Handle  uint64   `json:"handle"`
					Type    string   `json:"type"`
					Hook    string   `json:"hook"`
					Prio    int      `json:"prio"`
					Policy  string   `json:"policy"`
					Comment string   `json:"comment"`
					Flags   []string `json:"flags"`
				}
				if err := decodeStrictJSON(raw, &chain); err != nil {
					return fmt.Errorf("parse live chain metadata: %w", err)
				}
				if chain.Family != "inet" || chain.Table != owner.Table {
					return fmt.Errorf(
						"live chain %q targets %s %s, want inet %s",
						chain.Name,
						chain.Family,
						chain.Table,
						owner.Table,
					)
				}
				if chain.Handle == 0 {
					return fmt.Errorf("live guard chain %q has no stable handle", chain.Name)
				}
				if chain.Comment != "" || len(chain.Flags) != 0 {
					return fmt.Errorf(
						"live guard chain %q has unexpected comment or flags",
						chain.Name,
					)
				}
				expected, ok := expectedChains[chain.Name]
				if !ok {
					return fmt.Errorf("unexpected live guard chain %q", chain.Name)
				}
				if _, duplicate := chains[chain.Name]; duplicate {
					return fmt.Errorf("duplicate live guard chain %q", chain.Name)
				}
				actual := liveGuardChainShape{
					Type:     chain.Type,
					Hook:     chain.Hook,
					Priority: chain.Prio,
					Policy:   chain.Policy,
				}
				if actual != expected {
					return fmt.Errorf(
						"live guard chain %q shape=%#v, want %#v",
						chain.Name,
						actual,
						expected,
					)
				}
				chains[chain.Name] = actual
			default:
				return fmt.Errorf(
					"empty live guard table contains unexpected nft object type %q",
					objectType,
				)
			}
		}
	}
	if metainfoCount != 1 {
		return fmt.Errorf("live nft metainfo entries = %d, want 1", metainfoCount)
	}
	if tableCount != 1 {
		return fmt.Errorf("live guard table metadata entries = %d, want 1", tableCount)
	}
	if len(chains) != len(expectedChains) {
		return fmt.Errorf("live guard chains = %v, want exact input/output base chains", chains)
	}
	return nil
}

func TestValidateLiveGuardTableShapeJSON(t *testing.T) {
	owner := liveGuardShapeOwner()
	valid := liveGuardShapeFixture(owner, 41)
	if err := validateLiveGuardTableShapeJSON([]byte(valid), owner, 41); err != nil {
		t.Fatalf("valid live guard shape was rejected: %v", err)
	}

	duplicateChain := strings.Replace(valid, `"name": "output"`, `"name": "input"`, 1)
	duplicateChain = strings.Replace(duplicateChain, `"hook": "output"`, `"hook": "input"`, 1)
	const documentSuffix = "\n\t\t]\n\t}"
	if !strings.HasSuffix(valid, documentSuffix) {
		t.Fatal("live guard fixture suffix changed")
	}
	extraSet := strings.TrimSuffix(valid, documentSuffix) +
		`, {"set": {"family": "inet", "table": "` + owner.Table +
		`", "name": "unexpected"}}` + documentSuffix
	cases := map[string]string{
		"same-name-wrong-hook": strings.Replace(valid, `"hook": "input"`, `"hook": "forward"`, 1),
		"wrong-priority":       strings.Replace(valid, `"prio": -300`, `"prio": 0`, 1),
		"wrong-type":           strings.Replace(valid, `"type": "filter"`, `"type": "nat"`, 1),
		"wrong-policy":         strings.Replace(valid, `"policy": "accept"`, `"policy": "drop"`, 1),
		"duplicate-chain":      duplicateChain,
		"extra-set":            extraSet,
		"unknown-chain-field":  strings.Replace(valid, `"policy": "accept"`, `"policy": "accept", "unexpected": true`, 1),
		"duplicate-chain-key":  strings.Replace(valid, `"hook": "input"`, `"hook": "input", "hook": "forward"`, 1),
		"unsupported-schema":   strings.Replace(valid, `"json_schema_version": 1`, `"json_schema_version": 2`, 1),
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validateLiveGuardTableShapeJSON([]byte(document), owner, 41); err == nil {
				t.Fatalf("invalid live guard shape was accepted:\n%s", document)
			}
		})
	}
	if err := validateLiveGuardTableShapeJSON([]byte(valid), owner, 42); err == nil {
		t.Fatal("wrong expected handle was accepted")
	}
}

func liveGuardShapeOwner() ownerRecord {
	installationID := strings.Repeat("01", ownerTokenBytes)
	return ownerRecord{
		Version:        ownerRecordVersion,
		InstallationID: installationID,
		StateDir:       "/var/lib/wg-mix-ebpf-test-runs/shape/state",
		StateDirDevice: 1,
		StateDirInode:  2,
		Table:          ownedTableName(installationID),
		Marker:         ownedTableMarker(installationID),
	}
}

func liveGuardShapeFixture(owner ownerRecord, handle uint64) string {
	return fmt.Sprintf(`{
		"nftables": [
			{"metainfo": {"json_schema_version": 1}},
			{"table": {
				"family": "inet",
				"name": %q,
				"handle": %d,
				"comment": %q
			}},
			{"chain": {
				"family": "inet",
				"table": %q,
				"name": "input",
				"handle": 42,
				"type": "filter",
				"hook": "input",
				"prio": -300,
				"policy": "accept"
			}},
			{"chain": {
				"family": "inet",
				"table": %q,
				"name": "output",
				"handle": 43,
				"type": "filter",
				"hook": "output",
				"prio": -300,
				"policy": "accept"
			}}
		]
	}`, owner.Table, handle, owner.Marker, owner.Table, owner.Table)
}
