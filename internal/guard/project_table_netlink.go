package guard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/mdlayher/netlink"
)

const (
	nfnetlinkSubsystemNFTables = 10
	nfnetlinkVersion0          = 0
	nfprotoINet                = 1
	nftMessageNewTable         = 0
	nftMessageGetTable         = 1
	nftAttributeTableName      = 1
)

type nfTableQuery func(context.Context, netlink.Message) ([]netlink.Message, error)

// netlinkNFTableLister is intentionally narrower than google/nftables.Conn:
// the only operation it can issue is one NFT_MSG_GETTABLE dump. In particular,
// it has no command buffer and no Flush method capable of mutating the ruleset.
type netlinkNFTableLister struct {
	query nfTableQuery
}

func (l netlinkNFTableLister) ListTables(ctx context.Context) ([]NFTable, error) {
	if ctx == nil {
		return nil, errors.New("list nf_tables tables: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if l.query == nil {
		return nil, errors.New("list nf_tables tables: netlink query is nil")
	}

	request := netlink.Message{
		Header: netlink.Header{
			Type:  nftNetlinkMessageType(nftMessageGetTable),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: []byte{nfprotoINet, nfnetlinkVersion0, 0, 0},
	}
	messages, err := l.query(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("query inet nf_tables table inventory: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	tables := make([]NFTable, 0, len(messages))
	seen := make(map[string]struct{}, len(messages))
	for index, message := range messages {
		if message.Header.Flags&netlink.DumpInterrupted != 0 {
			return nil, errors.New("query inet nf_tables table inventory: netlink dump was interrupted")
		}
		if message.Header.Type != nftNetlinkMessageType(nftMessageNewTable) {
			return nil, fmt.Errorf(
				"parse inet nf_tables table inventory message %d: unexpected header type %d",
				index,
				message.Header.Type,
			)
		}
		name, err := parseINetNFTableMessage(message.Data)
		if err != nil {
			return nil, fmt.Errorf("parse inet nf_tables table inventory message %d: %w", index, err)
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("parse inet nf_tables table inventory: duplicate table %q", name)
		}
		seen[name] = struct{}{}
		tables = append(tables, NFTable{Family: nftTableFamilyINet, Name: name})
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].Name < tables[j].Name })
	return tables, nil
}

func nftNetlinkMessageType(message uint16) netlink.HeaderType {
	return netlink.HeaderType((nfnetlinkSubsystemNFTables << 8) | int(message))
}

func parseINetNFTableMessage(data []byte) (string, error) {
	if len(data) < 4 {
		return "", fmt.Errorf("nfgenmsg length = %d, want at least 4", len(data))
	}
	if data[0] != nfprotoINet {
		return "", fmt.Errorf("nfgenmsg family = %d, want inet (%d)", data[0], nfprotoINet)
	}
	if data[1] != nfnetlinkVersion0 {
		return "", fmt.Errorf("nfgenmsg version = %d, want %d", data[1], nfnetlinkVersion0)
	}

	decoder, err := netlink.NewAttributeDecoder(data[4:])
	if err != nil {
		return "", fmt.Errorf("decode table attributes: %w", err)
	}
	var name string
	nameSeen := false
	for decoder.Next() {
		if decoder.Type() != nftAttributeTableName {
			continue
		}
		if nameSeen {
			return "", errors.New("table attributes contain duplicate name")
		}
		nameSeen = true
		if decoder.TypeFlags() != 0 {
			return "", fmt.Errorf("table name attribute has flags 0x%x", decoder.TypeFlags())
		}
		raw := decoder.Bytes()
		if len(raw) < 2 || raw[len(raw)-1] != 0 {
			return "", errors.New("table name is not a non-empty NUL-terminated string")
		}
		if bytes.IndexByte(raw[:len(raw)-1], 0) >= 0 {
			return "", errors.New("table name contains an embedded NUL")
		}
		name = string(raw[:len(raw)-1])
	}
	if err := decoder.Err(); err != nil {
		return "", fmt.Errorf("decode table attributes: %w", err)
	}
	if !nameSeen {
		return "", errors.New("table attributes do not contain a name")
	}
	return name, nil
}
