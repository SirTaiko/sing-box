package zapret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	// EngineName is the only engine accepted in a zapret profile in this slice.
	EngineName = "zapret2"

	maxRecipeTokens      = 512
	maxRecipeTokenLength = 4096
)

// profileDocument is the on-disk profile format:
//
//	{
//	  "engine": "zapret2",
//	  "executable": "../zapret2/binaries/windows-x86_64/winws2.exe",
//	  "strategy_file": "lab.json"
//	}
//
// "executable" is resolved relative to the profile file directory and
// "strategy_file" is resolved relative to the same directory. The strategy
// file contains a JSON array of literal argv tokens; it is not the upstream
// @config format and it is never interpreted by a shell.
type profileDocument struct {
	Engine       string `json:"engine"`
	Executable   string `json:"executable"`
	StrategyFile string `json:"strategy_file"`
	// ReservationPorts optionally overrides the number of ports reserved per
	// socket family and protocol. Zero selects the 256-port default.
	ReservationPorts int `json:"reservation_ports,omitempty"`
}

type profile struct {
	path             string
	executable       string
	strategyFile     string
	strategyDir      string
	reservationPorts int
	tokens           []string
}

func loadProfile(profilePath string) (*profile, error) {
	if profilePath == "" {
		return nil, fmt.Errorf("zapret: empty profile path")
	}
	absolutePath, err := filepath.Abs(profilePath)
	if err != nil {
		return nil, fmt.Errorf("zapret: resolve profile path %q: %w", profilePath, err)
	}
	content, err := os.ReadFile(absolutePath)
	if err != nil {
		return nil, fmt.Errorf("zapret: read profile %q: %w", absolutePath, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var document profileDocument
	err = decoder.Decode(&document)
	if err != nil {
		return nil, fmt.Errorf("zapret: parse profile %q: %w", absolutePath, err)
	}
	err = expectJSONEOF(decoder)
	if err != nil {
		return nil, fmt.Errorf("zapret: parse profile %q: %w", absolutePath, err)
	}
	if document.Engine != EngineName {
		return nil, fmt.Errorf("zapret: profile %q: unsupported engine %q, this build accepts only %q", absolutePath, document.Engine, EngineName)
	}
	profileDir := filepath.Dir(absolutePath)
	if document.Executable == "" {
		return nil, fmt.Errorf("zapret: profile %q: missing executable", absolutePath)
	}
	executable, err := resolveProfilePath(profileDir, document.Executable)
	if err != nil {
		return nil, fmt.Errorf("zapret: profile %q: executable: %w", absolutePath, err)
	}
	executableInfo, err := os.Stat(executable)
	if err != nil {
		return nil, fmt.Errorf("zapret: profile %q: executable %q: %w", absolutePath, executable, err)
	}
	if !executableInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("zapret: profile %q: executable %q is not a regular file", absolutePath, executable)
	}
	if document.StrategyFile == "" {
		return nil, fmt.Errorf("zapret: profile %q: missing strategy_file", absolutePath)
	}
	if document.ReservationPorts != 0 && (document.ReservationPorts < 16 || document.ReservationPorts > 4096) {
		return nil, fmt.Errorf("zapret: profile %q: reservation_ports %d is outside 16..4096", absolutePath, document.ReservationPorts)
	}
	strategyFile, err := resolveProfilePath(profileDir, document.StrategyFile)
	if err != nil {
		return nil, fmt.Errorf("zapret: profile %q: strategy_file: %w", absolutePath, err)
	}
	strategyInfo, err := os.Stat(strategyFile)
	if err != nil {
		return nil, fmt.Errorf("zapret: profile %q: strategy_file %q: %w", absolutePath, strategyFile, err)
	}
	if !strategyInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("zapret: profile %q: strategy_file %q is not a regular file", absolutePath, strategyFile)
	}
	strategyDir := filepath.Dir(strategyFile)
	tokens, err := loadStrategy(strategyFile, strategyDir)
	if err != nil {
		return nil, fmt.Errorf("zapret: profile %q: %w", absolutePath, err)
	}
	return &profile{
		path:             absolutePath,
		executable:       executable,
		strategyFile:     strategyFile,
		strategyDir:      strategyDir,
		reservationPorts: document.ReservationPorts,
		tokens:           tokens,
	}, nil
}

func expectJSONEOF(decoder *json.Decoder) error {
	var trailing json.RawMessage
	err := decoder.Decode(&trailing)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("unexpected trailing JSON value")
}

func resolveProfilePath(baseDirectory string, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("empty path")
	}
	if strings.ContainsRune(value, 0) {
		return "", fmt.Errorf("path contains NUL")
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(baseDirectory, value)
	}
	return filepath.Clean(value), nil
}

func loadStrategy(strategyPath string, strategyDir string) ([]string, error) {
	content, err := os.ReadFile(strategyPath)
	if err != nil {
		return nil, fmt.Errorf("read strategy_file %q: %w", strategyPath, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	var tokens []string
	err = decoder.Decode(&tokens)
	if err != nil {
		return nil, fmt.Errorf("strategy_file %q must contain a JSON array of literal argument tokens: %w", strategyPath, err)
	}
	if tokens == nil {
		return nil, fmt.Errorf("strategy_file %q must contain a JSON array of literal argument tokens", strategyPath)
	}
	err = expectJSONEOF(decoder)
	if err != nil {
		return nil, fmt.Errorf("strategy_file %q: %w", strategyPath, err)
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("strategy_file %q contains no argument tokens", strategyPath)
	}
	if len(tokens) > maxRecipeTokens {
		return nil, fmt.Errorf("strategy_file %q contains %d tokens, limit is %d", strategyPath, len(tokens), maxRecipeTokens)
	}
	var (
		hasLuaInit   bool
		hasLuaDesync bool
		hasTCPFilter bool
		hasUDPFilter bool
	)
	for index, token := range tokens {
		name, err := validateRecipeToken(index, token, strategyDir)
		if err != nil {
			return nil, err
		}
		switch name {
		case "lua-init":
			hasLuaInit = true
		case "lua-desync":
			hasLuaDesync = true
		case "filter-tcp":
			hasTCPFilter = true
		case "filter-udp":
			hasUDPFilter = true
		}
	}
	if !hasLuaInit {
		return nil, fmt.Errorf("strategy_file %q must load stock Lua with at least one %q token", strategyPath, "--lua-init=@<file>")
	}
	if !hasLuaDesync {
		return nil, fmt.Errorf("strategy_file %q contains no %q token", strategyPath, "--lua-desync=")
	}
	if !hasTCPFilter && !hasUDPFilter {
		return nil, fmt.Errorf("strategy_file %q contains no %q or %q token", strategyPath, "--filter-tcp=", "--filter-udp=")
	}
	return tokens, nil
}

// recipeOptions lists the upstream options a profile may use. true means the
// option requires a value in the same token. Everything else, including every
// capture, queue, mark, interception, supervision, logging and
// config-redirection option, is owned by sing-box and rejected explicitly.
var recipeOptions = map[string]bool{
	"lua-init":                        true,
	"lua-desync":                      true,
	"lua-gc":                          true,
	"blob":                            true,
	"filter-l3":                       true,
	"filter-tcp":                      true,
	"filter-udp":                      true,
	"filter-icmp":                     true,
	"filter-ipp":                      true,
	"filter-l7":                       true,
	"ipset":                           true,
	"ipset-ip":                        true,
	"ipset-exclude":                   true,
	"ipset-exclude-ip":                true,
	"hostlist":                        true,
	"hostlist-domains":                true,
	"hostlist-exclude":                true,
	"hostlist-exclude-domains":        true,
	"hostlist-auto":                   true,
	"hostlist-auto-fail-threshold":    true,
	"hostlist-auto-fail-time":         true,
	"hostlist-auto-retrans-threshold": true,
	"hostlist-auto-retrans-reset":     true,
	"hostlist-auto-retrans-maxseq":    true,
	"hostlist-auto-incoming-maxseq":   true,
	"hostlist-auto-udp-out":           true,
	"hostlist-auto-udp-in":            true,
	"hostlist-auto-debug":             true,
	"payload":                         true,
	"payload-disable":                 true,
	"out-range":                       true,
	"in-range":                        true,
	"reasm-disable":                   true,
	"ctrack-timeouts":                 true,
	"ctrack-disable":                  true,
	"new":                             false,
	"skip":                            false,
	"name":                            true,
	"template":                        true,
	"cookie":                          true,
	"import":                          true,
	"comment":                         true,
}

var (
	portFilterPattern  = regexp.MustCompile(`^(\*|~?\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*)$`)
	luaFunctionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	l7FilterPattern    = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	blobNamePattern    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)
	hexPattern         = regexp.MustCompile(`^0[xX][0-9a-fA-F]+$`)
)

const (
	optionLuaInit         = "lua-init"
	optionLuaDesync       = "lua-desync"
	optionBlob            = "blob"
	optionFilterTCP       = "filter-tcp"
	optionFilterUDP       = "filter-udp"
	optionFilterL3        = "filter-l3"
	optionFilterL7        = "filter-l7"
	optionIPSet           = "ipset"
	optionIPSetExclude    = "ipset-exclude"
	optionHostlist        = "hostlist"
	optionHostlistExclude = "hostlist-exclude"
)

func validateRecipeToken(index int, token string, strategyDir string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("recipe token %d is empty", index)
	}
	if len(token) > maxRecipeTokenLength {
		return "", fmt.Errorf("recipe token %d is longer than %d bytes", index, maxRecipeTokenLength)
	}
	if strings.ContainsRune(token, 0) || strings.ContainsAny(token, "\r\n") {
		return "", fmt.Errorf("recipe token %d contains a NUL or line break", index)
	}
	if !strings.HasPrefix(token, "--") {
		return "", fmt.Errorf("recipe token %d %q is not a long option; the strategy file must contain complete literal tokens such as \"--filter-tcp=80,443\"; config-file redirection and positional arguments are not supported", index, token)
	}
	name := strings.TrimPrefix(token, "--")
	value := ""
	hasValue := false
	if separator := strings.IndexByte(name, '='); separator >= 0 {
		value = name[separator+1:]
		name = name[:separator]
		hasValue = true
	}
	requiresValue, allowed := recipeOptions[name]
	if !allowed {
		return "", fmt.Errorf("recipe token %d %q: option %q is not allowed in a zapret profile: capture, queue, mark, interception, supervision, logging and config-redirection options are owned by sing-box", index, token, "--"+name)
	}
	if requiresValue {
		if !hasValue {
			return "", fmt.Errorf("recipe token %d %q: option %q requires a value in the same token", index, token, "--"+name)
		}
		if value == "" {
			return "", fmt.Errorf("recipe token %d %q: option %q requires a non-empty value", index, token, "--"+name)
		}
	} else if hasValue {
		return "", fmt.Errorf("recipe token %d %q: option %q does not take a value", index, token, "--"+name)
	}
	switch name {
	case optionFilterTCP, optionFilterUDP:
		err := validatePortFilter(name, value)
		if err != nil {
			return "", fmt.Errorf("recipe token %d %q: %w", index, token, err)
		}
	case optionFilterL3:
		if value != "ipv4" && value != "ipv6" {
			return "", fmt.Errorf("recipe token %d %q: filter-l3 must be ipv4 or ipv6", index, token)
		}
	case optionFilterL7:
		for _, protocol := range strings.Split(value, ",") {
			if !l7FilterPattern.MatchString(protocol) {
				return "", fmt.Errorf("recipe token %d %q: invalid layer-7 protocol %q", index, token, protocol)
			}
		}
	case optionLuaInit:
		if !strings.HasPrefix(value, "@") {
			return "", fmt.Errorf("recipe token %d %q: inline Lua text is not supported; use %q with a file relative to the strategy directory", index, token, "--lua-init=@<file>")
		}
		_, err := strategyFile(strategyDir, strings.TrimPrefix(value, "@"))
		if err != nil {
			return "", fmt.Errorf("recipe token %d %q: %w", index, token, err)
		}
	case optionBlob:
		err := validateBlob(value, strategyDir)
		if err != nil {
			return "", fmt.Errorf("recipe token %d %q: %w", index, token, err)
		}
	case optionIPSet, optionIPSetExclude, optionHostlist, optionHostlistExclude:
		_, err := strategyFile(strategyDir, value)
		if err != nil {
			return "", fmt.Errorf("recipe token %d %q: %w", index, token, err)
		}
	case optionLuaDesync:
		functionName := value
		if separator := strings.IndexByte(functionName, ':'); separator >= 0 {
			functionName = functionName[:separator]
		}
		if !luaFunctionPattern.MatchString(functionName) {
			return "", fmt.Errorf("recipe token %d %q: invalid Lua desync function name %q", index, token, functionName)
		}
	}
	return name, nil
}

func validatePortFilter(name string, value string) error {
	if !portFilterPattern.MatchString(value) {
		return fmt.Errorf("%s has unsupported port syntax %q", name, value)
	}
	if value == "*" {
		return nil
	}
	for _, group := range strings.Split(value, ",") {
		group = strings.TrimPrefix(group, "~")
		if strings.Contains(group, "-") {
			parts := strings.SplitN(group, "-", 2)
			start, err := parsePort(parts[0])
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			end, err := parsePort(parts[1])
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if end < start {
				return fmt.Errorf("%s: invalid range %q", name, group)
			}
		} else {
			_, err := parsePort(group)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	return nil
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q", value)
	}
	return port, nil
}

func validateBlob(value string, strategyDir string) error {
	separator := strings.IndexByte(value, ':')
	if separator <= 0 {
		return fmt.Errorf("blob must use <name>:@<file> or <name>:0xHEX syntax")
	}
	name := value[:separator]
	if !blobNamePattern.MatchString(name) {
		return fmt.Errorf("invalid blob name %q", name)
	}
	source := value[separator+1:]
	if hexPattern.MatchString(source) {
		return nil
	}
	if offset := strings.IndexByte(source, '@'); offset > 0 && strings.HasPrefix(source, "+") {
		if _, err := strconv.Atoi(strings.TrimPrefix(source[:offset], "+")); err != nil {
			return fmt.Errorf("invalid blob offset in %q", source)
		}
		source = source[offset:]
	}
	if !strings.HasPrefix(source, "@") {
		return fmt.Errorf("blob %q must reference a file with @<file> or a hex literal with 0xHEX", name)
	}
	_, err := strategyFile(strategyDir, strings.TrimPrefix(source, "@"))
	return err
}

func strategyFile(strategyDir string, value string) (string, error) {
	path, err := resolveProfilePath(strategyDir, value)
	if err != nil {
		return "", fmt.Errorf("asset path: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("asset %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("asset %q is not a regular file", path)
	}
	return path, nil
}
