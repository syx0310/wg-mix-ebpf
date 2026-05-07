package wgconfig

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type Interface struct {
	FwMark     *uint32
	ListenPort *uint16
}

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
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
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
