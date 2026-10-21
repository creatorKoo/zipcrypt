package zipcrypt

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"
	"time"
)

var allMethods = []Method{None, ZipCrypto, AES128, AES192, AES256}

func testFiles() map[string][]byte {
	random := make([]byte, 1<<20)
	rand.Read(random)
	return map[string][]byte{
		"empty.txt":  {},
		"small.txt":  []byte("hello, 세계"),
		"random.bin": random,
		"repeat.txt": bytes.Repeat([]byte("compressible "), 50000),
	}
}

func sortedNames(files map[string][]byte) []string {
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// build writes files under "dir/" with the same Options for every entry.
func build(t testing.TB, method uint16, opt Options, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if _, err := w.CreateWith(&zip.FileHeader{Name: "dir/"}, opt); err != nil {
		t.Fatal(err)
	}
	for _, name := range sortedNames(files) {
		fh := &zip.FileHeader{Name: "dir/" + name, Method: method,
			Modified: time.Date(2024, 5, 17, 14, 30, 46, 0, time.Local)}
		fw, err := w.CreateWith(fh, opt)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func reader(t testing.TB, zipped []byte) *zip.Reader {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(zipped), int64(len(zipped)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func readAll(f *zip.File, password string) ([]byte, error) {
	rc, err := Open(f, password)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func password(m Method) string {
	if m == None {
		return ""
	}
	return "pw"
}

func TestRoundTrip(t *testing.T) {
	files := testFiles()
	for _, m := range allMethods {
		for _, tc := range []struct {
			name   string
			method uint16
			opt    Options
		}{
			{"store", zip.Store, Options{}},
			{"nocompression", zip.Deflate, Options{NoCompression: true}},
			{"default", zip.Deflate, Options{}},
			{"best", zip.Deflate, Options{Level: 9}},
		} {
			t.Run(m.String()+"/"+tc.name, func(t *testing.T) {
				opt := tc.opt
				opt.Method, opt.Password = m, password(m)
				r := reader(t, build(t, tc.method, opt, files))
				for _, f := range r.File {
					encrypted := f.Flags&0x1 != 0
					if strings.HasSuffix(f.Name, "/") {
						if encrypted {
							t.Errorf("%s: directory is encrypted", f.Name)
						}
						continue
					}
					if encrypted != (m != None) {
						t.Errorf("%s: encrypted = %v", f.Name, encrypted)
					}
					want := files[strings.TrimPrefix(f.Name, "dir/")]
					if f.UncompressedSize64 != uint64(len(want)) {
						t.Errorf("%s: UncompressedSize64 = %d, want %d", f.Name, f.UncompressedSize64, len(want))
					}
					got, err := readAll(f, password(m))
					if err != nil {
						t.Fatalf("%s: %v", f.Name, err)
					}
					if !bytes.Equal(got, want) {
						t.Errorf("%s: contents differ", f.Name)
					}
				}
			})
		}
	}
}

// The recorded sizes include the encryption overhead.
func TestSizes(t *testing.T) {
	data := []byte("exactly these bytes")
	for _, tc := range []struct {
		m        Method
		overhead int
	}{
		{ZipCrypto, 12},      // encryption header
		{AES128, 8 + 2 + 10}, // salt, password verifier, authentication code
		{AES256, 16 + 2 + 10},
	} {
		r := reader(t, build(t, zip.Store, Options{Method: tc.m, Password: "pw"}, map[string][]byte{"a": data}))
		if f, want := r.File[1], uint64(len(data)+tc.overhead); f.CompressedSize64 != want {
			t.Errorf("%v: CompressedSize64 = %d, want %d", tc.m, f.CompressedSize64, want)
		}
	}
}

// Level 0 means the level archive/zip uses, and NoCompression stores blocks
// uncompressed whatever the level.
func TestLevels(t *testing.T) {
	files := map[string][]byte{"a.txt": bytes.Repeat([]byte("compressible "), 50000)}
	size := func(opt Options) uint64 {
		return reader(t, build(t, zip.Deflate, opt, files)).File[1].CompressedSize64
	}
	if zero, five := size(Options{}), size(Options{Level: 5}); zero != five {
		t.Errorf("Level 0 wrote %d bytes, Level 5 wrote %d", zero, five)
	}
	raw := uint64(len(files["a.txt"]))
	if n := size(Options{NoCompression: true, Level: 9}); n < raw {
		t.Errorf("NoCompression compressed %d bytes to %d", raw, n)
	}
	if n := size(Options{}); n >= raw/10 {
		t.Errorf("default level compressed %d bytes to only %d", raw, n)
	}
}

func TestWrongPassword(t *testing.T) {
	files := map[string][]byte{"a.txt": []byte("secret")}
	for _, m := range []Method{AES128, AES256} {
		r := reader(t, build(t, zip.Deflate, Options{Method: m, Password: "right"}, files))
		if _, err := Open(r.File[1], "wrong"); !errors.Is(err, ErrPassword) {
			t.Errorf("%v: err = %v, want ErrPassword", m, err)
		}
	}
	// ZipCrypto checks only one byte, so 1 wrong password in 256 gets past the
	// header. It must still never yield the plain data without an error.
	r := reader(t, build(t, zip.Deflate, Options{Method: ZipCrypto, Password: "right"}, files))
	rejected := 0
	for i := range 50 {
		got, err := readAll(r.File[1], fmt.Sprintf("wrong%d", i))
		if errors.Is(err, ErrPassword) {
			rejected++
		} else if err == nil && bytes.Equal(got, files["a.txt"]) {
			t.Fatalf("wrong password %d decrypted the data", i)
		}
	}
	if rejected < 40 {
		t.Errorf("only %d of 50 wrong passwords were rejected by the header check", rejected)
	}
}

func TestAESDetectsTampering(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 1000)
	zipped := build(t, zip.Store, Options{Method: AES256, Password: "pw"}, map[string][]byte{"a": data})
	off, err := reader(t, zipped).File[1].DataOffset()
	if err != nil {
		t.Fatal(err)
	}
	zipped[off+16+2+500] ^= 1 // inside the ciphertext
	if _, err := readAll(reader(t, zipped).File[1], "pw"); !errors.Is(err, ErrAuthentication) {
		t.Errorf("err = %v, want ErrAuthentication", err)
	}
}

func TestPlainEntriesThroughEmbeddedWriter(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	fw, _ := w.Create("plain.txt")
	fw.Write(bytes.Repeat([]byte("abc"), 1000))
	w.Close()
	f := reader(t, buf.Bytes()).File[0]
	if f.Flags&0x1 != 0 || f.CompressedSize64 >= f.UncompressedSize64 {
		t.Errorf("plain entry: flags %#x, %d -> %d bytes", f.Flags, f.UncompressedSize64, f.CompressedSize64)
	}
	if got, err := readAll(f, ""); err != nil || len(got) != 3000 {
		t.Errorf("read %d bytes, err %v", len(got), err)
	}
}

// flate writers come from a pool per level. Entries that mix levels and
// methods must each start from a clean writer.
func TestManyEntriesMixedLevels(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	opts := []Options{
		{}, {NoCompression: true}, {Level: 9},
		{Method: ZipCrypto, Password: "pw"}, {Method: ZipCrypto, Password: "pw", NoCompression: true},
		{Method: AES256, Password: "pw"}, {Method: AES128, Password: "pw", Level: 1},
	}
	want := map[string][]byte{}
	for i := range 60 {
		name := fmt.Sprintf("f%02d.txt", i)
		data := bytes.Repeat([]byte(fmt.Sprintf("entry %d ", i)), 200+i*31)
		want[name] = data
		fw, err := w.CreateWith(&zip.FileHeader{Name: name, Method: zip.Deflate}, opts[i%len(opts)])
		if err != nil {
			t.Fatal(err)
		}
		fw.Write(data)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for _, f := range reader(t, buf.Bytes()).File {
		got, err := readAll(f, "pw")
		if err != nil || !bytes.Equal(got, want[f.Name]) {
			t.Errorf("%s: err %v, equal %v", f.Name, err, bytes.Equal(got, want[f.Name]))
		}
	}
}

func TestOptionErrors(t *testing.T) {
	w := NewWriter(io.Discard)
	for _, tc := range []struct {
		name   string
		method uint16
		opt    Options
	}{
		{"encryption without password", zip.Deflate, Options{Method: ZipCrypto}},
		// A password that is silently ignored would leave the data readable.
		{"password without encryption", zip.Deflate, Options{Password: "pw"}},
		{"unknown encryption", zip.Deflate, Options{Method: AES256 + 1, Password: "pw"}},
		{"unsupported compression", 12, Options{}}, // bzip2
		{"invalid level", zip.Deflate, Options{Level: 10}},
	} {
		if _, err := w.CreateWith(&zip.FileHeader{Name: "a", Method: tc.method}, tc.opt); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}
