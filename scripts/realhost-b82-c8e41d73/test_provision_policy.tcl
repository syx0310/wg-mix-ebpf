#!/usr/bin/expect -f

proc fail {message} {
    puts stderr "provision policy test failed: $message"
    exit 1
}

proc payload {mode missing plan_kind write_kind} {
    set lines [list "mode=$mode" "missing_packages=$missing"]
    if {$plan_kind eq "ready"} {
        lappend lines "plan_apt_commands=skipped reason=fixed-package-set-already-installed"
    } elseif {$plan_kind eq "install"} {
        lappend lines "plan_command=A0 argv=fixed-update"
        lappend lines "plan_command=A1 argv=fixed-simulate"
        lappend lines "plan_command=A2 argv=fixed-install"
    } elseif {$plan_kind ne "broken"} {
        fail "unknown plan fixture"
    }
    lappend lines "plan_complete planned_commands_executed=0 writes=0 automatic_cleanup=0"
    if {$write_kind eq "apply"} {
        lappend lines "write_start timestamp=t0 description=update"
        lappend lines "write_finish timestamp=t1 description=update exit=0"
        lappend lines "write_start timestamp=t2 description=install"
        lappend lines "write_finish timestamp=t3 description=install exit=0"
        lappend lines "provisioning completed"
    } elseif {$write_kind ne "none"} {
        fail "unknown write fixture"
    }
    return [join $lines "\n"]
}

proc expect_value {label expected script} {
    if {[catch {uplevel 1 $script} actual]} {
        fail "$label returned error $actual"
    }
    if {$actual ne $expected} {
        fail "$label returned $actual, expected $expected"
    }
}

proc expect_error {label expected script} {
    if {![catch {uplevel 1 $script} actual]} {
        fail "$label unexpectedly returned $actual"
    }
    if {$actual ne $expected} {
        fail "$label error $actual, expected $expected"
    }
}

if {$argc != 1} {
    fail "usage: test_provision_policy.tcl LOCKED_TRANSPORT"
}
set transport [file normalize [lindex $argv 0]]
if {[file type $transport] ne "file"} {
    fail "transport is not a regular file"
}
source $transport

proc expect_signaled_wait_rejected {operation assertion signal_name} {
    log_user 0
    spawn -noecho /usr/bin/python3 -B -I -c \
        "import os, signal; os.kill(os.getpid(), signal.$signal_name)"
    set child_id $spawn_id
    expect -i $child_id eof
    if {[catch {wait -i $child_id} wait_status]} {
        log_user 1
        fail "$operation/$assertion/$signal_name could not collect wait status"
    }
    log_user 1
    if {![catch {clean_child_exit_status $wait_status} error] ||
        $error ne "child-wait-status"} {
        fail "$operation/$assertion/$signal_name accepted signaled wait status $wait_status"
    }
}

foreach {operation assertion} {
    stale-package-root none
    stale-realnic-run-roots empty
    veth-run none
    routed-run none
} {
    foreach signal_name {SIGTERM SIGKILL} {
        expect_signaled_wait_rejected $operation $assertion $signal_name
    }
}

set initial " clang gcc golang-go iperf3 libbpf-dev llvm make pkg-config shellcheck wireguard-tools"
expect_value ready none {
    provision_plan_policy [payload check "" ready none] check
}
expect_value initial initial {
    provision_plan_policy [payload check $initial install none] check
}
expect_value iperf3 iperf3 {
    provision_plan_policy [payload check " iperf3" install none] check
}
expect_error unexpected unexpected-missing-set {
    provision_plan_policy [payload check " clang" install none] check
}
expect_error check-failed-plan already-ready-plan {
    provision_plan_policy [payload check "" broken none] check
}
expect_error check-wrote check-write-evidence {
    provision_plan_policy [payload check " iperf3" install apply] check
}
expect_value explicit-apply iperf3 {
    provision_plan_policy [payload apply " iperf3" install apply] apply
}
expect_error apply-without-missing apply-write-evidence {
    provision_plan_policy [payload apply "" ready none] apply
}
expect_value canonical-path "" {
    assert_output \
        "exact:/run/wg-mix-ebpf-source-bootstrap-c8e41d73/provision-ubuntu-test-host.sh" \
        "/run/wg-mix-ebpf-source-bootstrap-c8e41d73/provision-ubuntu-test-host.sh\n"
}
expect_error path-drift exact-output-mismatch {
    assert_output \
        "exact:/run/wg-mix-ebpf-source-bootstrap-c8e41d73/provision-ubuntu-test-host.sh" \
        "/run/wg-mix-ebpf-source-bootstrap-c8e41d73/alternate.sh\n"
}
expect_error stat-drift exact-output-mismatch {
    assert_output "exact:root:root:700:1:regular file" \
        "siyixuan:siyixuan:700:1:regular file\n"
}
expect_error sha-drift exact-output-mismatch {
    assert_output \
        "exact:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  /run/wg-mix-ebpf-source-bootstrap-c8e41d73/provision-ubuntu-test-host.sh" \
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  /run/wg-mix-ebpf-source-bootstrap-c8e41d73/provision-ubuntu-test-host.sh\n"
}

puts "provision check/apply output policy and ordinary signaled-child cuts: PASS"
