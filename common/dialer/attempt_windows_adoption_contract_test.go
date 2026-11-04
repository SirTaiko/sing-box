package dialer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// qualifiedAdoptionSymbols is the exact enumerated exception boundary of the
// direct-owned Windows adoption. The order is the call order of the bridge.
var qualifiedAdoptionSymbols = []struct {
	directive string
	signature string
}{
	{"//go:linkname goNetNewFD net.newFD", "func goNetNewFD(sysfd syscall.Handle, family, sotype int, network string) (unsafe.Pointer, error)"},
	{"//go:linkname goNetFDInit net.(*netFD).init", "func goNetFDInit(fd unsafe.Pointer) error"},
	{"//go:linkname goNetFDSetAddr net.(*netFD).setAddr", "func goNetFDSetAddr(fd unsafe.Pointer, local, remote net.Addr)"},
	{"//go:linkname goNetFDClose net.(*netFD).Close", "func goNetFDClose(fd unsafe.Pointer) error"},
	{"//go:linkname goNetNewTCPConn net.newTCPConn", "func goNetNewTCPConn(fd unsafe.Pointer, idle time.Duration, cfg net.KeepAliveConfig, preHook func(unsafe.Pointer), hook func(net.KeepAliveConfig)) *net.TCPConn"},
}

// TestW01AdoptionUsesExactlyTheQualifiedSymbols is the qualification regression
// of the direct-owned adoption boundary. It fails when the carrier is adopted
// through net.FileConn/os.NewFile, when a second internal symbol is referenced,
// when the exact five declarations or their signatures change, when private
// layouts/offsets/uintptr round-trips appear, or when the exact-version and
// fail-closed build constraints disappear.
func TestW01AdoptionUsesExactlyTheQualifiedSymbols(t *testing.T) {
	adoption, err := os.ReadFile("attempt_windows.go")
	if err != nil {
		t.Fatalf("read attempt_windows.go: %v", err)
	}
	ctor, err := os.ReadFile("attempt_windows_adoption_ctor.go")
	if err != nil {
		t.Fatalf("read attempt_windows_adoption_ctor.go: %v", err)
	}
	unsupported, err := os.ReadFile("attempt_windows_adoption_ctor_unsupported.go")
	if err != nil {
		t.Fatalf("read attempt_windows_adoption_ctor_unsupported.go: %v", err)
	}
	ctorText := string(ctor)

	for _, source := range []struct {
		name string
		text []byte
	}{
		{"attempt_windows.go", adoption},
		{"attempt_windows_adoption_ctor.go", ctor},
	} {
		text := string(source.text)
		for _, prohibited := range []string{
			"net.FileConn(",
			"os.NewFile(",
			"net.newWindowsFile",
			"net_newWindowsFile",
			"dupFileSocket",
			"reflect.SliceHeader",
			"(*netFD)(",
		} {
			if strings.Contains(text, prohibited) {
				t.Fatalf("%s still references the superseded FileConn/duplicate boundary %q", source.name, prohibited)
			}
		}
		// No mirrored standard-library layout and no pointer round-trip may be
		// introduced at this boundary.
		for _, prohibited := range []string{
			"unsafe.Sizeof(",
			"unsafe.Offsetof(",
			"uintptr(fd)",
			"unsafe.Pointer(uintptr",
			"reflect.",
		} {
			if strings.Contains(text, prohibited) {
				t.Fatalf("%s contains the prohibited mirrored-layout/pointer conversion %q", source.name, prohibited)
			}
		}
		if strings.Contains(text, "type netFD struct") || strings.Contains(text, "type pollFD struct") || strings.Contains(text, "type tcpConn struct") {
			t.Fatalf("%s mirrors a standard-library private structure", source.name)
		}
	}

	for _, symbol := range qualifiedAdoptionSymbols {
		if got := strings.Count(ctorText, symbol.directive); got != 1 {
			t.Fatalf("directive %q count = %d, want exactly one", symbol.directive, got)
		}
		if !strings.Contains(ctorText, symbol.signature) {
			t.Fatalf("qualified signature missing: %q", symbol.signature)
		}
	}
	if !strings.Contains(ctorText, "//go:build windows && go1.26 && !go1.27") {
		t.Fatal("the direct-owned adoption bridge must be compiled only for windows and the audited Go 1.26.x toolchain")
	}
	if !strings.Contains(ctorText, "adoptOwnedCarrier") && !strings.Contains(string(adoption), "adoptOwnedCarrier") {
		t.Fatal("the adoption seam must consume the carrier through the direct-owned bridge")
	}
	if !strings.Contains(string(adoption), "func bridgeOwnedCarrier(api socketAdoptionAPI") {
		t.Fatal("the direct bridge routine with the six-function socketAdoptionAPI is missing")
	}
	if !strings.Contains(string(unsupported), "//go:build windows && (!go1.26 || go1.27)") {
		t.Fatal("an unqualified Windows toolchain must be refused by a complementary build constraint")
	}
	if !strings.Contains(string(unsupported), "newOwnedSocketConn") {
		t.Fatal("the unqualified toolchain file must fail closed on the missing direct-owned bridge")
	}

	// Exactly the five executable linkname directives may exist in the package.
	// Any second internal symbol would be an unreviewed extension of the
	// accepted exception boundary.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	var directives []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		text, readErr := os.ReadFile(name)
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		for _, line := range strings.Split(string(text), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "//go:linkname") {
				directives = append(directives, line)
			}
		}
	}
	if len(directives) != len(qualifiedAdoptionSymbols) {
		t.Fatalf("go:linkname directives = %d (%v), want exactly the five qualified net symbols", len(directives), directives)
	}
	for index, symbol := range qualifiedAdoptionSymbols {
		if directives[index] != symbol.directive {
			t.Fatalf("directive %d = %q, want %q", index, directives[index], symbol.directive)
		}
	}

	// The exact-version qualification gate and its fifteen pinned standard
	// library sources must stay in the helper.
	qualification, err := os.ReadFile(filepath.Join("..", "..", "release", "check-windows-adoption-go.py"))
	if err != nil {
		t.Fatalf("read the Windows toolchain qualification helper: %v", err)
	}
	for _, pin := range []string{
		`EXPECTED_VERSION = "go1.26.9"`,
		`EXPECTED_GOOS = "windows"`,
		`EXPECTED_GOARCH = "amd64"`,
		`REQUIRED_LDFLAG = "-checklinkname=0"`,
		`"net/fd_windows.go"`,
		`"net/fd_posix.go"`,
		`"net/tcpsock.go"`,
		`"net/dial.go"`,
		`"net/tcpsockopt_posix.go"`,
		`"net/tcpsockopt_windows.go"`,
		`"net/tcpsock_windows.go"`,
		`"net/net.go"`,
		`"internal/poll/fd_windows.go"`,
		`"internal/poll/fd_poll_runtime.go"`,
		`"internal/poll/fd_mutex.go"`,
		`"internal/poll/hook_windows.go"`,
		`"runtime/netpoll_windows.go"`,
		`"runtime/netpoll.go"`,
		`"cmd/link/internal/loader/loader.go"`,
	} {
		if !strings.Contains(string(qualification), pin) {
			t.Fatalf("the qualification helper no longer pins %q", pin)
		}
	}
	for _, hash := range []string{
		"8008f4a0bd9fc58a23b3fea17ffdb15e4739c19585c60589b764076d225972ff",
		"31e1ad8e0ed8b6a86d9f547c9695a1d67b35a553e0e251ea66362fb22c5354f2",
		"0c3392bd7c2966f894e01ea27514623cf09dc2660e426049219f7e5ee3ec0f74",
		"9963e94645bb8620e61bf219236a5d859b17de161344d433b93bedd6f3ad1e1e",
		"16d8565b480a743e5d75ccc457fbb2dc46f4fcf3a681ea01bf45be0f057e348d",
		"4492fd3fe6d4e7e131a04547f0f2e6c7ea36bae8d442569112e1168fed401c5e",
		"91054c727154f7e7b3ad3dd44a19ebf0e8846b11df7b9bb79b30b6b887fb3762",
		"35a3d5047c156a1395c4c197fad5a99e123567a12ae7bc08ba7d5c723281ae03",
		"a6ed6ff45e39c6c49eb42c43bc07f2290315edcd63a2fb6e4028782ac3a8e950",
		"88fda43019c5dcf42545effdebd1747aaea377560dd041a35df8499538ee07c5",
		"ad10a59470d3848a745f9549afcee67aae9553e385ec41988d7e5266c2bc3902",
		"b63c32b4a5f03051f4bd78bb4440232fd929ba90be8e66cb404aa2f31dc12c5b",
		"9a0727cc4b9fb93de904123083f4f9fe05af1f9b14a67218a3cb812eb1f9ce62",
		"f7c606d3fa0a3b9499fd5f42b81918a98f0b99a6029fca2010cabc710fc9ea65",
		"0b6b271aee4951e7202e854795c008733f0f2a6f5726603c7067eda3a2413dfe",
	} {
		if !strings.Contains(string(qualification), hash) {
			t.Fatalf("the qualification helper no longer pins standard-library SHA-256 %q", hash)
		}
	}
}

// TestW01ContractPathsExist keeps the static contract test honest if the files
// are renamed: it fails instead of silently skipping.
func TestW01ContractPathsExist(t *testing.T) {
	for _, name := range []string{
		"attempt_windows.go",
		"attempt_windows_adoption_ctor.go",
		"attempt_windows_adoption_ctor_unsupported.go",
	} {
		if _, err := os.Stat(filepath.Join(".", name)); err != nil {
			t.Fatalf("adoption contract file %s is missing: %v", name, err)
		}
	}
}
