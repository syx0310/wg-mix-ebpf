package wgconfig

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type Interface struct {
	FwMark     *uint32
	ListenPort *uint16
}

var hookFwMarkPattern = regexp.MustCompile(`(?:^|[;&|]\s*)(?:\S*/)?wg\s+set\s+(?:%i|[^\s;&|]+)\s+fwmark\s+([^\s;&|]+)`)

func ParseFile(path string) (*Interface, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

func Parse(r io.Reader) (*Interface, error) {
	cfg := &Interface{}
	scanner := bufio.NewScanner(r)
	section := ""
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := cleanLine(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section != "Interface" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: missing =", lineNo)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "FwMark":
			mark, err := ParseFwMark(value)
			if err != nil {
				return nil, fmt.Errorf("line %d: parse FwMark: %w", lineNo, err)
			}
			cfg.FwMark = &mark
		case "ListenPort":
			port, err := parseListenPort(value)
			if err != nil {
				return nil, fmt.Errorf("line %d: parse ListenPort: %w", lineNo, err)
			}
			cfg.ListenPort = &port
		case "PostUp":
			mark, ok, err := parseHookFwMark(value)
			if err != nil {
				return nil, fmt.Errorf("line %d: parse PostUp fwmark: %w", lineNo, err)
			}
			if !ok || cfg.FwMark != nil {
				continue
			}
			cfg.FwMark = &mark
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func parseHookFwMark(command string) (uint32, bool, error) {
	match := hookFwMarkPattern.FindStringSubmatch(command)
	if match == nil {
		return 0, false, nil
	}
	mark, err := ParseFwMark(unquoteShellWord(match[1]))
	if err != nil {
		return 0, false, err
	}
	return mark, true, nil
}

func unquoteShellWord(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if (value[0] == '\'' && value[len(value)-1] == '\'') ||
			(value[0] == '"' && value[len(value)-1] == '"') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func cleanLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	return line
}

func ParseFwMark(raw string) (uint32, error) {
	raw = strings.TrimSpace(raw)
	if strings.EqualFold(raw, "off") {
		return 0, nil
	}
	v, err := strconv.ParseUint(raw, 0, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

func parseListenPort(raw string) (uint16, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(v), nil
}
