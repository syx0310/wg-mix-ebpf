package guard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type nftJSONDocument struct {
	Nftables json.RawMessage `json:"nftables"`
}

type nftJSONMetainfo struct {
	Version           string `json:"version"`
	ReleaseName       string `json:"release_name"`
	JSONSchemaVersion int    `json:"json_schema_version"`
}

func parseNftJSONItems(data []byte) ([]map[string]json.RawMessage, error) {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, err
	}
	var document nftJSONDocument
	if err := decodeNftJSON(data, &document); err != nil {
		return nil, fmt.Errorf("parse nft JSON document: %w", err)
	}
	trimmed := bytes.TrimSpace(document.Nftables)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, errors.New("nft JSON document has no nftables array")
	}
	var items []map[string]json.RawMessage
	if err := decodeNftJSON(trimmed, &items); err != nil {
		return nil, fmt.Errorf("parse nftables array: %w", err)
	}
	if items == nil {
		return nil, errors.New("nft JSON document has a null nftables array")
	}
	return items, nil
}

func validateNftJSONMetainfo(raw json.RawMessage) error {
	var metainfo nftJSONMetainfo
	if err := decodeNftJSON(raw, &metainfo); err != nil {
		return fmt.Errorf("parse nft JSON metainfo: %w", err)
	}
	if metainfo.JSONSchemaVersion < 1 {
		return fmt.Errorf(
			"nft JSON schema version = %d, want at least 1",
			metainfo.JSONSchemaVersion,
		)
	}
	return nil
}

// decodeStrictJSON is retained for the nft object decoders in executor.go and
// the live-shape tests. "Strict" here means strict JSON syntax, typed known
// fields, a single top-level value, and (through parseNftJSONItems) unique keys.
// It deliberately does not reject unknown fields: nft owns this external JSON
// schema and may add metadata without changing the fields used for ownership
// or inventory decisions. Project-owned owner records use their own strict
// decoder in ownership.go and continue to reject unknown fields.
func decodeStrictJSON(data []byte, target any) error {
	return decodeNftJSON(data, target)
}

func decodeNftJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains more than one top-level value")
		}
		return fmt.Errorf("parse trailing JSON data: %w", err)
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanUniqueJSONValue(decoder, "$"); err != nil {
		return fmt.Errorf("validate unique nft JSON keys: %w", err)
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("validate trailing nft JSON data: %w", err)
		}
		return fmt.Errorf("nft JSON contains a second top-level token %v", token)
	}
	return nil
}

func scanUniqueJSONValue(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key at %s is not a string", path)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q at %s", key, path)
			}
			seen[key] = struct{}{}
			if err := scanUniqueJSONValue(decoder, path+"."+key); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("object at %s ended with %v", path, end)
		}
	case '[':
		for index := 0; decoder.More(); index++ {
			if err := scanUniqueJSONValue(
				decoder,
				fmt.Sprintf("%s[%d]", path, index),
			); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("array at %s ended with %v", path, end)
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q at %s", delimiter, path)
	}
	return nil
}
