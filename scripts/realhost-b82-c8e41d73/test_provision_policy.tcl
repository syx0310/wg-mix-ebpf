#!/usr/bin/expect -f

proc test_fail {message} {
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
        test_fail "unknown plan fixture"
    }
    lappend lines "plan_complete planned_commands_executed=0 writes=0 automatic_cleanup=0"
    if {$write_kind eq "apply"} {
        lappend lines "write_start timestamp=t0 description=update"
        lappend lines "write_finish timestamp=t1 description=update exit=0"
        lappend lines "write_start timestamp=t2 description=install"
        lappend lines "write_finish timestamp=t3 description=install exit=0"
        lappend lines "provisioning completed"
    } elseif {$write_kind ne "none"} {
        test_fail "unknown write fixture"
    }
    return [join $lines "\n"]
}

proc expect_value {label expected script} {
    if {[catch {uplevel 1 $script} actual]} {
        test_fail "$label returned error $actual"
    }
    if {$actual ne $expected} {
        test_fail "$label returned $actual, expected $expected"
    }
}

proc expect_error {label expected script} {
    if {![catch {uplevel 1 $script} actual]} {
        test_fail "$label unexpectedly returned $actual"
    }
    if {$actual ne $expected} {
        test_fail "$label error $actual, expected $expected"
    }
}

set ::TEST_SCRIPT_PATH [file normalize [info script]]
if {$argc != 1 && !($argc == 3 && [lindex $argv 1] eq "--capture-case")} {
    test_fail "usage: test_provision_policy.tcl LOCKED_TRANSPORT ?--capture-case NAME?"
}
set transport [file normalize [lindex $argv 0]]
if {[file type $transport] ne "file"} {
    test_fail "transport is not a regular file"
}
set capture_case [expr {$argc == 3 ? [lindex $argv 2] : ""}]
source $transport

set prompt_fixture_values [dict create \
    target_user siyixuan \
    target_host 192.168.10.82 \
    remote_package_dir /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61 \
    local_package_dir /private/tmp/wg-mix-ebpf-capture-prompt-fixture \
    remote_source /run/wg-mix-ebpf-source-stages/c8e41d73/source \
    realnic_acceptance_py_path scripts/realhost-b82-acceptance-v1/realnic_acceptance.py \
    integration_commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]
lassign [build_operation $prompt_fixture_values \
    bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
    realnic-plan none] prompt_kind prompt_spawn_argv prompt_limit prompt_assertion \
    prompt_timeout
set prompt_target_index [lsearch -exact $prompt_spawn_argv \
    siyixuan@192.168.10.82]
set prompt_remote_argv [lrange $prompt_spawn_argv [expr {$prompt_target_index + 1}] end]
set prompt_remote_command [join $prompt_remote_argv " "]
set prompt_remote_words [split $prompt_remote_command " "]
set prompt_option_index [lsearch -exact $prompt_remote_words -p]
if {$prompt_kind ne "ssh" || $prompt_limit != 2 || $prompt_assertion ne "none" ||
    $prompt_timeout != 2400 || $prompt_target_index < 1 || $prompt_option_index < 0 ||
    [lindex $prompt_remote_words [expr {$prompt_option_index + 1}]] ne
        "B82_V6_SUDO_PASSWORD:" ||
    [regexp {\s} [lindex $prompt_remote_words [expr {$prompt_option_index + 1}]]]} {
    test_fail "RealNIC sudo prompt does not survive OpenSSH remote-command serialization"
}

set ::CAPTURE_CHILD_PROGRAM {
import json
import os
import signal
import sys
import termios
import time

scenario = sys.argv[1]
expected_password = bytes.fromhex(sys.argv[2])

attributes = termios.tcgetattr(0)
attributes[0] &= ~(termios.ICRNL | termios.INLCR | termios.IGNCR)
attributes[1] &= ~termios.OPOST
attributes[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON)
termios.tcsetattr(0, termios.TCSANOW, attributes)
active = termios.tcgetattr(0)
if (active[1] & termios.OPOST) or (active[3] & (termios.ECHO | termios.ECHONL)):
    os._exit(40)

ssh_prompt = b"siyixuan@192.168.10.82's password: "
sudo_prompt = b"B82_V6_SUDO_PASSWORD:"

def write_all(payload):
    view = memoryview(payload)
    while view:
        count = os.write(1, view)
        view = view[count:]

def write_parts(parts, delay=0.04):
    for part in parts:
        write_all(part)
        time.sleep(delay)

def prompt_and_read(prompt, bytewise=False):
    if bytewise:
        write_parts([bytes([octet]) for octet in prompt], 0.002)
    else:
        write_all(prompt)
    wire = bytearray()
    while not wire or wire[-1] != 13:
        octet = os.read(0, 1)
        if not octet or len(wire) > 4096:
            os._exit(41)
        wire.extend(octet)
    if bytes(wire) != expected_password + b"\r":
        os._exit(42)

def one_prompt_prefix(bytewise=False):
    prompt_and_read(ssh_prompt, bytewise)
    write_all(b"\r\n")

if scenario == "one_prompt":
    one_prompt_prefix()
    write_all(b'{"case":"one"}\r\n')
elif scenario == "two_prompts":
    prompt_and_read(ssh_prompt)
    write_all(b"\r\n")
    prompt_and_read(sudo_prompt)
    write_all(b'\r\n{"case":"two"}\r\n')
elif scenario == "prompt_bytewise":
    one_prompt_prefix(True)
    write_all(b'{"case":"bytewise"}\r\n')
elif scenario == "crlf_split":
    prompt_and_read(ssh_prompt)
    write_parts([b"\r", b"\n"])
    prompt_and_read(sudo_prompt)
    write_parts([b"\r", b"\n"])
    write_all(b'{"case":"crlf-split"}\r\n')
elif scenario == "crlf_prompt_same_chunk":
    prompt_and_read(ssh_prompt)
    write_all(b"\r\n" + sudo_prompt)
    wire = bytearray()
    while not wire or wire[-1] != 13:
        octet = os.read(0, 1)
        if not octet or len(wire) > 4096:
            os._exit(41)
        wire.extend(octet)
    if bytes(wire) != expected_password + b"\r":
        os._exit(42)
    write_all(b'\r\n{"case":"same-chunk"}\r\n')
elif scenario == "utf8_wire":
    one_prompt_prefix()
    write_all(b'{"case":"utf8-wire"}\r\n')
elif scenario == "large_8192":
    one_prompt_prefix()
    write_all(b"{" + (b"a" * 8189) + b"}\r\n")
elif scenario == "boundary_16m":
    one_prompt_prefix()
    write_all(b"{" + (b"a" * 16777213) + b"}\r\n")
elif scenario == "invalid_utf8":
    one_prompt_prefix()
    write_all(b"{\xff}\r\n")
elif scenario == "zero_prompts":
    write_all(b'{"case":"zero"}\r\n')
elif scenario == "prompt_crlf_same_chunk":
    # An initial prompt contaminated by CRLF in the same write is not an exact
    # credential frame and must not lead to captured payload stdout.
    write_all(ssh_prompt + b"\r\n")
elif scenario == "three_prompts":
    prompt_and_read(ssh_prompt)
    write_all(b"\r\n" + sudo_prompt)
    wire = bytearray()
    while not wire or wire[-1] != 13:
        octet = os.read(0, 1)
        if not octet or len(wire) > 4096:
            os._exit(41)
        wire.extend(octet)
    if bytes(wire) != expected_password + b"\r":
        os._exit(42)
    write_all(b"\r\n" + sudo_prompt)
    time.sleep(3)
elif scenario == "nul_payload":
    one_prompt_prefix()
    write_all(b"{\x00}\r\n")
elif scenario == "lone_cr":
    prompt_and_read(ssh_prompt)
    write_all(b'\r{"case":"lone-cr"}\r\n')
elif scenario == "lone_lf":
    prompt_and_read(ssh_prompt)
    write_all(b'\n{"case":"lone-lf"}\r\n')
elif scenario == "boundary_16m_plus_one":
    one_prompt_prefix()
    write_all(b"{" + (b"a" * 16777214) + b"}\r\n")
elif scenario == "full_buffer_40m_open":
    one_prompt_prefix()
    # No CRLF or EOF follows the payload start. The bounded 40 MiB write keeps
    # the child open while Expect's 16 MiB match buffer reaches full_buffer.
    write_all(bytes([123]) + (b"a" * 41943039))
    time.sleep(3)
elif scenario == "sigterm":
    one_prompt_prefix()
    write_all(bytes([123]))
    os.kill(os.getpid(), signal.SIGTERM)
elif scenario == "sigkill":
    one_prompt_prefix()
    write_all(bytes([123]))
    os.kill(os.getpid(), signal.SIGKILL)
elif scenario == "initial_timeout":
    time.sleep(3)
elif scenario == "payload_timeout":
    one_prompt_prefix()
    write_all(bytes([123]))
    time.sleep(3)
elif scenario == "child_nonzero":
    one_prompt_prefix()
    write_all(b'{"case":"nonzero"}\r\n')
    os._exit(23)
elif scenario in {"raw_secret", "raw_secret_split"}:
    one_prompt_prefix()
    prefix = b'{"leak":"'
    suffix = b'"}\r\n'
    if scenario == "raw_secret":
        write_all(prefix + expected_password + suffix)
    else:
        split = max(1, len(expected_password) // 2)
        write_parts([prefix + expected_password[:split],
                     expected_password[split:] + suffix], 0.10)
elif scenario == "raw_secret_cross_append":
    one_prompt_prefix()
    # The leading left brace is consumed in capture_child_payload; the rest is
    # appended at EOF, so the secret exists only after the second append.
    write_all(expected_password + b"\r\n")
elif scenario in {"json_secret", "json_secret_split"}:
    one_prompt_prefix()
    escaped = json.dumps(expected_password.decode("utf-8"),
                         ensure_ascii=True)[1:-1].encode("ascii")
    prefix = b'{"leak":"'
    suffix = b'"}\r\n'
    if scenario == "json_secret":
        write_all(prefix + escaped + suffix)
    else:
        split = max(1, len(escaped) // 2)
        write_parts([prefix + escaped[:split], escaped[split:] + suffix], 0.10)
elif scenario == "json_secret_cross_append":
    one_prompt_prefix()
    escaped = json.dumps(expected_password.decode("utf-8"),
                         ensure_ascii=True)[1:-1].encode("ascii")
    # As above, the unescaped leading left brace is the first append.
    write_all(escaped + b"\r\n")
else:
    os._exit(43)
}

proc synthetic_capture_password {} {
    # Synthetic UTF-8 only: braces, p, a-umlaut, ss, quote, backslash,
    # grinning face. Braces make cross-append leak tests reach across the
    # separately consumed payload-start byte.
    return [binary format H* 7b70c3a47373225cf09f98807d]
}

proc spawn_capture_fixture {case_name password} {
    binary scan $password H* password_hex
    log_user 0
    spawn -noecho /usr/bin/python3 -B -I -c $::CAPTURE_CHILD_PROGRAM \
        $case_name $password_hex
    return $spawn_id
}

proc expect_capture_success {case_name prompt_limit expected_prompts expected_payload} {
    set password [synthetic_capture_password]
    set child_id [spawn_capture_fixture $case_name $password]
    set result [capture_child_payload $child_id $password $prompt_limit 10]
    log_user 1
    lassign $result actual_payload actual_prompts raw_bytes
    binary scan $actual_payload H* actual_hex
    binary scan $expected_payload H* expected_hex
    if {$actual_hex ne $expected_hex || $actual_prompts != $expected_prompts ||
        $raw_bytes != [expr {[string bytelength $expected_payload] +
            (2 * $expected_prompts) + 1}]} {
        test_fail "$case_name capture result mismatch"
    }
}

proc expect_capture_sized_success {case_name payload_bytes body_bytes} {
    set password [synthetic_capture_password]
    set child_id [spawn_capture_fixture $case_name $password]
    set result [capture_child_payload $child_id $password 1 40]
    log_user 1
    lassign $result actual_payload actual_prompts raw_bytes
    binary scan [string range $actual_payload 0 7] H* prefix_hex
    binary scan [string range $actual_payload end-7 end] H* suffix_hex
    set expected_payload "{[string repeat a $body_bytes]}\n"
    if {[string bytelength $actual_payload] != $payload_bytes ||
        $actual_payload ne $expected_payload || $actual_prompts != 1 ||
        $raw_bytes != ($payload_bytes + 3) ||
        $prefix_hex ne "7b61616161616161" ||
        $suffix_hex ne "6161616161617d0a"} {
        test_fail "$case_name sized capture result mismatch"
    }
    set expected_payload ""
    set actual_payload ""
}

proc read_binary_file {path} {
    set channel [open $path r]
    fconfigure $channel -encoding binary -translation binary
    set payload [read $channel]
    close $channel
    return $payload
}

proc capture_case_settings {case_name} {
    switch -- $case_name {
        initial_timeout - payload_timeout {
            return [list 1 1]
        }
        three_prompts {
            return [list 2 5]
        }
        default {
            return [list 1 40]
        }
    }
}

proc run_isolated_capture_case {case_name} {
    set password [synthetic_capture_password]
    lassign [capture_case_settings $case_name] prompt_limit timeout_seconds
    set child_id [spawn_capture_fixture $case_name $password]
    set result [capture_child_payload $child_id $password $prompt_limit $timeout_seconds]
    log_user 1
    return $result
}

proc expect_capture_rejection {case_name expected_rc {expected_reason ""}} {
    set expected_temp_parent [file normalize /tmp]
    set temp_root [exec /usr/bin/mktemp -d \
        /tmp/wg-mix-ebpf-capture-test.XXXXXX]
    if {[file dirname $temp_root] ne $expected_temp_parent ||
        ![regexp {^wg-mix-ebpf-capture-test\.[A-Za-z0-9]+$} \
            [file tail $temp_root]]} {
        test_fail "$case_name temporary directory mismatch"
    }
    set stdout_path [file join $temp_root stdout.bin]
    set stderr_path [file join $temp_root stderr.bin]
    set command [list /usr/bin/expect $::TEST_SCRIPT_PATH $::TRANSPORT_SCRIPT_PATH \
        --capture-case $case_name]
    set caught [catch {exec {*}$command >$stdout_path 2>$stderr_path} message options]
    set stdout_payload [read_binary_file $stdout_path]
    set stderr_payload [read_binary_file $stderr_path]
    file delete -- $stdout_path
    file delete -- $stderr_path
    file delete -- $temp_root
    if {!$caught || ![dict exists $options -errorcode] ||
        [lindex [dict get $options -errorcode] 0] ne "CHILDSTATUS"} {
        test_fail "$case_name did not exit as a rejected child"
    }
    set actual_rc [lindex [dict get $options -errorcode] 2]
    set password [synthetic_capture_password]
    set password_json_escape [python_json_escape_utf8_content $password]
    if {$actual_rc != $expected_rc || $stdout_payload ne "" ||
        [string first $password $stderr_payload] >= 0 ||
        [string first $password_json_escape $stderr_payload] >= 0} {
        test_fail "$case_name rejection mismatch"
    }
    if {$expected_reason ne ""} {
        set expected_stderr \
            "B82_V6_TRANSPORT_STOP reason=$expected_reason rc=$expected_rc\n"
        if {$stderr_payload ne $expected_stderr} {
            test_fail "$case_name rejection reason mismatch"
        }
    }
}

if {$capture_case ne ""} {
    run_isolated_capture_case $capture_case
    test_fail "$capture_case unexpectedly returned a capture payload"
}

expect_capture_success one_prompt 1 1 \
    [binary format H* 7b2263617365223a226f6e65227d0a]
expect_capture_success two_prompts 2 2 \
    [binary format H* 7b2263617365223a2274776f227d0a]
expect_capture_success prompt_bytewise 1 1 \
    [binary format H* 7b2263617365223a226279746577697365227d0a]
expect_capture_success crlf_split 2 2 \
    [binary format H* 7b2263617365223a2263726c662d73706c6974227d0a]
expect_capture_success crlf_prompt_same_chunk 2 2 \
    [binary format H* 7b2263617365223a2273616d652d6368756e6b227d0a]
expect_capture_success utf8_wire 1 1 \
    [binary format H* 7b2263617365223a22757466382d77697265227d0a]
expect_capture_success invalid_utf8 1 1 [binary format H* 7bff7d0a]
expect_capture_sized_success large_8192 8192 8189
expect_capture_sized_success boundary_16m 16777216 16777213

foreach {case_name expected_rc} {
    zero_prompts 78
    prompt_crlf_same_chunk 78
    three_prompts 78
    nul_payload 78
    lone_cr 78
    lone_lf 78
    sigterm 78
    sigkill 78
    initial_timeout 124
    payload_timeout 124
    child_nonzero 23
    raw_secret 78
    raw_secret_split 78
    raw_secret_cross_append 78
    json_secret 78
    json_secret_split 78
    json_secret_cross_append 78
} {
    expect_capture_rejection $case_name $expected_rc
}
expect_capture_rejection boundary_16m_plus_one 78 \
    capture-framing-capture-payload-frame
expect_capture_rejection full_buffer_40m_open 78 capture-full-buffer

proc expect_signaled_wait_rejected {operation assertion signal_name} {
    log_user 0
    spawn -noecho /usr/bin/python3 -B -I -c \
        "import os, signal; os.kill(os.getpid(), signal.$signal_name)"
    set child_id $spawn_id
    expect -i $child_id eof
    if {[catch {wait -i $child_id} wait_status]} {
        log_user 1
        test_fail "$operation/$assertion/$signal_name could not collect wait status"
    }
    log_user 1
    if {![catch {clean_child_exit_status $wait_status} error] ||
        $error ne "child-wait-status"} {
        test_fail "$operation/$assertion/$signal_name accepted signaled wait status $wait_status"
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

puts "provision check/apply, ordinary signaled-child, and local capture PTY policy: PASS"
