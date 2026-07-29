package pinidentity

import "testing"

func TestCanonicalAndFileNames(t *testing.T) {
	canonical, err := Canonical(42, 99, "wg-mix-ebpf-a")
	if err != nil {
		t.Fatal(err)
	}
	if canonical != "wg-mix-ebpf-pin-v1:42:99:wg-mix-ebpf-a" {
		t.Fatalf("canonical identity = %q", canonical)
	}
	key, err := Key(42, 99, "wg-mix-ebpf-a")
	if err != nil {
		t.Fatal(err)
	}
	if key != "0587a9fb34e37f032795767bfd901660a37e065b3faecd363ba302147f6bcbc3" {
		t.Fatalf("resource key = %q", key)
	}
	if !ValidKey(key) || ValidKey("0587a9") {
		t.Fatalf("key validation mismatch for %q", key)
	}
	lockName, err := LockFileName(42, 99, "wg-mix-ebpf-a")
	if err != nil {
		t.Fatal(err)
	}
	if lockName != key+".lock" {
		t.Fatalf("lock filename = %q", lockName)
	}
	ownerName, err := OwnerFileName(42, 99, "wg-mix-ebpf-a")
	if err != nil {
		t.Fatal(err)
	}
	if ownerName != key+".owner.json" {
		t.Fatalf("owner filename = %q", ownerName)
	}
}

func TestCanonicalRejectsUnsafeIdentity(t *testing.T) {
	tests := []struct {
		device uint64
		inode  uint64
		base   string
	}{
		{device: 0, inode: 1, base: "wg-mix-ebpf-a"},
		{device: 1, inode: 0, base: "wg-mix-ebpf-a"},
		{device: 1, inode: 1, base: ""},
		{device: 1, inode: 1, base: "."},
		{device: 1, inode: 1, base: ".."},
		{device: 1, inode: 1, base: "wg-mix-ebpf/a"},
		{device: 1, inode: 1, base: "wg mix"},
		{device: 1, inode: 1, base: "wg-mix-\u00e9"},
	}
	for _, tt := range tests {
		if _, err := Canonical(tt.device, tt.inode, tt.base); err == nil {
			t.Fatalf("unsafe identity unexpectedly accepted: %#v", tt)
		}
	}
}
