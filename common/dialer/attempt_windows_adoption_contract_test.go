package dialer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestW01AdoptionUsesOnlyTheQualifiedSocketConstructor is the disposal-contract
// regression for the Windows adoption carrier. It fails when the carrier is
// constructed through os.NewFile (generic "file"/"pipe" classification, so
// File.Close and the File finalizer call CloseHandle on a Winsock descriptor),
// when a second internal constructor is referenced, or when the exact-version
// and fail-closed build constraints disappear.
func TestW01AdoptionUsesOnlyTheQualifiedSocketConstructor(t *testing.T) {
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

	for _, source := range []struct {
		name string
		text []byte
	}{
		{"attempt_windows.go", adoption},
		{"attempt_windows_adoption_ctor.go", ctor},
	} {
		if strings.Contains(string(source.text), "os.NewFile(") {
			t.Fatalf("%s constructs the adoption carrier with os.NewFile: a Winsock descriptor would be closed with CloseHandle", source.name)
		}
	}

	const linkname = "//go:linkname netNewWindowsFile net.newWindowsFile"
	if got := strings.Count(string(ctor), linkname); got != 1 {
		t.Fatalf("linkname declarations = %d, want exactly one %q", got, linkname)
	}
	const signature = "func netNewWindowsFile(handle syscall.Handle, name string) *os.File"
	if !strings.Contains(string(ctor), signature) {
		t.Fatalf("constructor signature missing: the audited Go1.26.9 symbol is %q", signature)
	}
	if !strings.Contains(string(ctor), "//go:build windows && go1.26 && !go1.27") {
		t.Fatal("the socket-aware constructor must be compiled only for windows and the audited Go 1.26.x toolchain")
	}
	if !strings.Contains(string(ctor), "newAdoptionFile = newSocketAdoptionFile") && !strings.Contains(string(adoption), "newAdoptionFile = newSocketAdoptionFile") {
		t.Fatal("the adoption seam must use the socket-aware constructor")
	}
	if !strings.Contains(string(unsupported), "//go:build windows && (!go1.26 || go1.27)") {
		t.Fatal("an unqualified Windows toolchain must be refused by a complementary build constraint")
	}
	if !strings.Contains(string(unsupported), "newSocketAdoptionFile") {
		t.Fatal("the unqualified toolchain file must fail closed on the missing socket-aware constructor")
	}
	if !strings.Contains(string(adoption), "retireSocketDescriptor") {
		t.Fatal("the carrier retirement error contract must be applied by the adoption")
	}

	// Exactly one executable linkname directive may exist in the package: the
	// enumerated socket constructor. Any second internal symbol would be an
	// unreviewed extension of the accepted exception boundary.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	directives := 0
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
			if strings.HasPrefix(line, "//go:linkname") {
				directives++
				if !strings.Contains(line, "net.newWindowsFile") {
					t.Fatalf("%s: unexpected internal symbol reference %q", name, line)
				}
			}
		}
	}
	if directives != 1 {
		t.Fatalf("go:linkname directives = %d, want exactly the one qualified socket constructor", directives)
	}

	// The exact-version qualification gate and the audited constructor source
	// fingerprint must stay pinned together with the symbol.
	qualification, err := os.ReadFile(filepath.Join("..", "..", "release", "check-windows-adoption-go.py"))
	if err != nil {
		t.Fatalf("read the Windows toolchain qualification helper: %v", err)
	}
	for _, pin := range []string{
		`EXPECTED_VERSION = "go1.26.9"`,
		"c22ecd7dd18b10a3091f7c1d7deae868a64e7adcf046c8ca62d3666e73edfcc7",
		"33005305d01549b938d1f6c08fa7b3ac0dd899f4575ebf9cf9522ec1cbac23e8",
	} {
		if !strings.Contains(string(qualification), pin) {
			t.Fatalf("the qualification helper no longer pins %q", pin)
		}
	}
}

// dupFileSocket API substitution seams: only the standard library's external
// calls are replaced. The control flow of both bodies below is copied verbatim
// from the pinned Go sources.
type dupRawConn interface {
	Control(func(fd uintptr)) error
}

type dupFileHandle interface {
	Fd()
	SyscallConn() (dupRawConn, error)
}

type fakeDupFile struct {
	raw       dupRawConn
	connErr   error
	fdCalls   int
	syscallOK bool
}

func (f *fakeDupFile) Fd() { f.fdCalls++ }

func (f *fakeDupFile) SyscallConn() (dupRawConn, error) {
	if f.connErr != nil {
		return nil, f.connErr
	}
	return f.raw, nil
}

type fakeDupRawConn struct {
	controlErr error
	ran        bool
}

func (c *fakeDupRawConn) Control(callback func(fd uintptr)) error {
	if c.controlErr != nil {
		return c.controlErr
	}
	c.ran = true
	callback(7)
	return nil
}

// dupFileSocketGo1255 is the Go1.25.5 net/file_windows.go body with only
// dupSocket and the File API substituted. It copies syserr only when Control
// itself failed, so a failing duplication behind a successful Control is lost
// and the caller receives handle 0 with a nil error.
func dupFileSocketGo1255(file dupFileHandle, dupSocket func(uintptr) (uintptr, error)) (uintptr, error) {
	file.Fd()

	sc, err := file.SyscallConn()
	if err != nil {
		return 0, err
	}

	var h uintptr
	var syserr error
	err = sc.Control(func(fd uintptr) {
		h, syserr = dupSocket(fd)
	})
	if err != nil {
		err = syserr
	}
	if err != nil {
		return 0, err
	}
	return h, nil
}

// dupFileSocketGo1269 is the Go1.26.9 net/file_windows.go body with the same
// external substitution. It copies syserr when Control succeeded, so the actual
// duplication error is propagated and no descriptor is owned by the caller.
func dupFileSocketGo1269(file dupFileHandle, dupSocket func(uintptr) (uintptr, error)) (uintptr, error) {
	file.Fd()

	sc, err := file.SyscallConn()
	if err != nil {
		return 0, err
	}

	var h uintptr
	var syserr error
	err = sc.Control(func(fd uintptr) {
		h, syserr = dupSocket(fd)
	})
	if err == nil {
		err = syserr
	}
	if err != nil {
		return 0, err
	}
	return h, nil
}

// TestW03FileConnDuplicationErrorPropagation pins why the Windows adoption
// requires the qualified Go1.26.9 toolchain: the FileConn duplication must
// report its own failure instead of returning a zero descriptor with a nil
// error. The Go1.25.5 body is the semantic negative control. The boundary is
// API substitution, not a replacement of the standard-library control flow.
func TestW03FileConnDuplicationErrorPropagation(t *testing.T) {
	dupErr := errors.New("injected WSADuplicateSocket failure")

	t.Run("go1269-propagates-duplication-error", func(t *testing.T) {
		file := &fakeDupFile{raw: &fakeDupRawConn{}}
		handle, err := dupFileSocketGo1269(file, func(uintptr) (uintptr, error) {
			return 0, dupErr
		})
		if !errors.Is(err, dupErr) {
			t.Fatalf("error = %v, want the duplication error", err)
		}
		if handle != 0 {
			t.Fatalf("handle = %d, want 0", handle)
		}
	})

	t.Run("go1255-loses-duplication-error", func(t *testing.T) {
		file := &fakeDupFile{raw: &fakeDupRawConn{}}
		handle, err := dupFileSocketGo1255(file, func(uintptr) (uintptr, error) {
			return 0, dupErr
		})
		if err != nil || handle != 0 {
			t.Fatalf("Go1.25.5 body = (%#x, %v), want the documented (0, nil) defect this toolchain qualification removes", handle, err)
		}
	})

	t.Run("go1269-propagates-control-error", func(t *testing.T) {
		controlErr := errors.New("injected Control failure")
		file := &fakeDupFile{raw: &fakeDupRawConn{controlErr: controlErr}}
		if _, err := dupFileSocketGo1269(file, func(uintptr) (uintptr, error) { return 0, dupErr }); !errors.Is(err, controlErr) {
			t.Fatalf("error = %v, want the Control error", err)
		}
	})

	t.Run("go1255-loses-control-error", func(t *testing.T) {
		controlErr := errors.New("injected Control failure")
		file := &fakeDupFile{raw: &fakeDupRawConn{controlErr: controlErr}}
		if _, err := dupFileSocketGo1255(file, func(uintptr) (uintptr, error) { return 0, dupErr }); err != nil {
			t.Fatalf("error = %v, want the documented lost-Control-error defect", err)
		}
	})

	t.Run("success-control", func(t *testing.T) {
		file := &fakeDupFile{raw: &fakeDupRawConn{}}
		for name, body := range map[string]func(dupFileHandle, func(uintptr) (uintptr, error)) (uintptr, error){
			"go1269": dupFileSocketGo1269,
			"go1255": dupFileSocketGo1255,
		} {
			handle, err := body(file, func(uintptr) (uintptr, error) { return 0x99, nil })
			if err != nil || handle != 0x99 {
				t.Fatalf("%s success = (%#x, %v), want (0x99, nil)", name, handle, err)
			}
			if file.fdCalls == 0 {
				t.Fatalf("%s did not disassociate the IOCP through Fd", name)
			}
		}
	})
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
