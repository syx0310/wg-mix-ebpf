package guard

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mdlayher/netlink"
)

func TestNetlinkNFTableListerUsesSingleReadOnlyGetTableDump(t *testing.T) {
	queries := 0
	lister := netlinkNFTableLister{query: func(ctx context.Context, request netlink.Message) ([]netlink.Message, error) {
		queries++
		if ctx != t.Context() {
			t.Fatal("lister did not forward the caller context")
		}
		if request.Header.Type != nftNetlinkMessageType(nftMessageGetTable) {
			t.Fatalf("netlink request type = %d, want NFT_MSG_GETTABLE", request.Header.Type)
		}
		if request.Header.Flags != netlink.Request|netlink.Dump {
			t.Fatalf("netlink request flags = %v, want request|dump", request.Header.Flags)
		}
		if want := []byte{nfprotoINet, nfnetlinkVersion0, 0, 0}; !bytes.Equal(request.Data, want) {
			t.Fatalf("netlink request data = %v, want %v", request.Data, want)
		}
		return []netlink.Message{
			nfTableReply(t, "z-last"),
			nfTableReply(t, TableName),
			nfTableReply(t, "a-first"),
		}, nil
	}}

	tables, err := lister.ListTables(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if queries != 1 {
		t.Fatalf("netlink queries = %d, want exactly 1", queries)
	}
	want := []string{"a-first", TableName, "z-last"}
	if len(tables) != len(want) {
		t.Fatalf("tables = %v, want %v", tables, want)
	}
	for index := range want {
		if tables[index] != (NFTable{Family: "inet", Name: want[index]}) {
			t.Fatalf("tables[%d] = %#v, want inet/%s", index, tables[index], want[index])
		}
	}
}

func TestNetlinkNFTableListerRejectsMalformedOrIncompleteDump(t *testing.T) {
	missingNameAttrs, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: 99, Data: []byte{1}}})
	if err != nil {
		t.Fatal(err)
	}
	duplicateNameAttrs, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: nftAttributeTableName, Data: []byte("one\x00")},
		{Type: nftAttributeTableName, Data: []byte("two\x00")},
	})
	if err != nil {
		t.Fatal(err)
	}
	unterminatedNameAttrs, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: nftAttributeTableName, Data: []byte("unterminated")},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		messages []netlink.Message
	}{
		{
			name: "wrong-message-type",
			messages: []netlink.Message{{
				Header: netlink.Header{Type: nftNetlinkMessageType(nftMessageGetTable)},
				Data:   []byte{nfprotoINet, nfnetlinkVersion0, 0, 0},
			}},
		},
		{
			name: "interrupted-dump",
			messages: []netlink.Message{{
				Header: netlink.Header{Type: nftNetlinkMessageType(nftMessageNewTable), Flags: netlink.DumpInterrupted},
				Data:   []byte{nfprotoINet, nfnetlinkVersion0, 0, 0},
			}},
		},
		{
			name: "short-nfgenmsg",
			messages: []netlink.Message{{
				Header: netlink.Header{Type: nftNetlinkMessageType(nftMessageNewTable)},
				Data:   []byte{nfprotoINet},
			}},
		},
		{
			name: "wrong-family",
			messages: []netlink.Message{{
				Header: netlink.Header{Type: nftNetlinkMessageType(nftMessageNewTable)},
				Data:   append([]byte{2, nfnetlinkVersion0, 0, 0}, missingNameAttrs...),
			}},
		},
		{
			name: "unknown-version",
			messages: []netlink.Message{{
				Header: netlink.Header{Type: nftNetlinkMessageType(nftMessageNewTable)},
				Data:   append([]byte{nfprotoINet, 1, 0, 0}, missingNameAttrs...),
			}},
		},
		{
			name: "missing-name",
			messages: []netlink.Message{{
				Header: netlink.Header{Type: nftNetlinkMessageType(nftMessageNewTable)},
				Data:   append([]byte{nfprotoINet, nfnetlinkVersion0, 0, 0}, missingNameAttrs...),
			}},
		},
		{
			name: "duplicate-name",
			messages: []netlink.Message{{
				Header: netlink.Header{Type: nftNetlinkMessageType(nftMessageNewTable)},
				Data:   append([]byte{nfprotoINet, nfnetlinkVersion0, 0, 0}, duplicateNameAttrs...),
			}},
		},
		{
			name: "unterminated-name",
			messages: []netlink.Message{{
				Header: netlink.Header{Type: nftNetlinkMessageType(nftMessageNewTable)},
				Data:   append([]byte{nfprotoINet, nfnetlinkVersion0, 0, 0}, unterminatedNameAttrs...),
			}},
		},
		{
			name:     "duplicate-table",
			messages: []netlink.Message{nfTableReply(t, "duplicate"), nfTableReply(t, "duplicate")},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lister := netlinkNFTableLister{query: func(context.Context, netlink.Message) ([]netlink.Message, error) {
				return test.messages, nil
			}}
			if tables, err := lister.ListTables(t.Context()); err == nil {
				t.Fatalf("malformed dump was accepted: %#v", tables)
			}
		})
	}
}

func TestNetlinkNFTableListerPropagatesQueryErrors(t *testing.T) {
	sentinel := errors.New("permission denied")
	lister := netlinkNFTableLister{query: func(context.Context, netlink.Message) ([]netlink.Message, error) {
		return nil, sentinel
	}}
	_, err := lister.ListTables(t.Context())
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "inventory") {
		t.Fatalf("query error = %v, want wrapped sentinel", err)
	}
}

func nfTableReply(t *testing.T, name string) netlink.Message {
	t.Helper()
	attributes, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: nftAttributeTableName,
		Data: append(append([]byte(nil), name...), 0),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return netlink.Message{
		Header: netlink.Header{Type: nftNetlinkMessageType(nftMessageNewTable)},
		Data:   append([]byte{nfprotoINet, nfnetlinkVersion0, 0, 0}, attributes...),
	}
}
