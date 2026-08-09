package dataplane

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestFakeTCPVethRouteHelperIsExactOwnedAndExplicitlyReversible(t *testing.T) {
	bytes, err := os.ReadFile("../../scripts/faketcp-veth-route-helper.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(bytes)

	for _, forbidden := range []string{
		"rm -rf", "find -delete", "xargs rm", "rsync --delete", "trap ",
		"chroot", "nsenter", "sudo", "ssh ", "route flush", "route replace",
		"ens33", "47.116.202.155", "credientials/", "|| true", "/dev/null",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("route helper contains forbidden operation %q", forbidden)
		}
	}
	for _, want := range []string{
		"10.0.0.2/32", "10.0.0.1/32", "table main", "scope link",
		"proto \"${ROUTE_PROTOCOL}\"", "metric \"${ROUTE_A_METRIC}\"",
		"metric \"${ROUTE_B_METRIC}\"", "route add", "route del",
		"validate_veth", "veth-a-identity", "veth-b-identity", "owner-drift",
		"faketcp-route-a-before.out", "faketcp-route-b-before.out",
		"validate_route_absent", "validate_route_owned", "/usr/bin/jq -e",
		"route-preexisting", "no automatic teardown", "restore_one_route b",
		"restore_one_route a", "faketcp-routes-restored.v1", "commands_are_review_templates=1",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("route helper is missing contract %q", want)
		}
	}
	if strings.Index(script, "restore_one_route b") >= strings.Index(script, "restore_one_route a") {
		t.Fatal("route helper does not restore in explicit reverse order")
	}
	if got := len(regexp.MustCompile(`/usr/sbin/ip -4 route add`).FindAllStringIndex(script, -1)); got != 4 {
		// Each exact add appears once in the plan and once in execution.
		t.Fatalf("exact route-add argv occurrences=%d, want 4", got)
	}
	if got := len(regexp.MustCompile(`/usr/sbin/ip -4 route del`).FindAllStringIndex(script, -1)); got != 3 {
		// Two plan templates share one parameterized execution implementation.
		t.Fatalf("exact route-del argv occurrences=%d, want 3", got)
	}
}
