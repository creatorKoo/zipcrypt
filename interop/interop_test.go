package interop

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/creatorKoo/zipcrypt"
	yeka "github.com/yeka/zip"
)

const password = "pw1234"

func testFiles() map[string][]byte {
	photo := make([]byte, 300_000)
	rand.Read(photo)
	return map[string][]byte{
		"한글.txt":    bytes.Repeat([]byte("한글 문서 "), 5000),
		"사진.jpg":    photo,
		"empty.txt": {},
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

func write(t testing.TB, w io.Writer, method uint16, opt zipcrypt.Options, files map[string][]byte) {
	t.Helper()
	zw := zipcrypt.NewWriter(w)
	for _, name := range sortedNames(files) {
		fh := &zip.FileHeader{Name: name, Method: method, Modified: time.Now()}
		// SetMode also records Unix as the creating system. Without it the
		// entry claims to come from MS-DOS, and Info-ZIP unzip on macOS then
		// decodes the UTF-8 names as an old DOS code page.
		fh.SetMode(0o644)
		fw, err := zw.CreateWith(fh, opt)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

// samples are the archives check.sh hands to other tools.
var samples = []struct {
	name   string
	method uint16
	opt    zipcrypt.Options
}{
	{"zc-deflate.zip", zip.Deflate, zipcrypt.Options{Method: zipcrypt.ZipCrypto, Password: password}},
	{"zc-nocompression.zip", zip.Deflate, zipcrypt.Options{Method: zipcrypt.ZipCrypto, Password: password, NoCompression: true}},
	{"zc-store.zip", zip.Store, zipcrypt.Options{Method: zipcrypt.ZipCrypto, Password: password}},
	{"aes128-store.zip", zip.Store, zipcrypt.Options{Method: zipcrypt.AES128, Password: password}},
	{"aes192-deflate.zip", zip.Deflate, zipcrypt.Options{Method: zipcrypt.AES192, Password: password}},
	{"aes256-deflate.zip", zip.Deflate, zipcrypt.Options{Method: zipcrypt.AES256, Password: password}},
}

// yeka/zip must read what zipcrypt writes.
func TestYekaReadsZipcrypt(t *testing.T) {
	files := testFiles()
	for _, s := range samples {
		var buf bytes.Buffer
		write(t, &buf, s.method, s.opt, files)
		r, err := yeka.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range r.File {
			f.SetPassword(password)
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("%s %s: %v", s.name, f.Name, err)
			}
			got, err := io.ReadAll(rc)
			rc.Close()
			if err != nil || !bytes.Equal(got, files[f.Name]) {
				t.Errorf("%s %s: yeka read differs (err %v)", s.name, f.Name, err)
			}
		}
	}
}

// And zipcrypt must read what yeka/zip writes.
func TestZipcryptReadsYeka(t *testing.T) {
	files := testFiles()
	for _, enc := range []yeka.EncryptionMethod{
		yeka.StandardEncryption, yeka.AES128Encryption, yeka.AES192Encryption, yeka.AES256Encryption,
	} {
		var buf bytes.Buffer
		w := yeka.NewWriter(&buf)
		for _, name := range sortedNames(files) {
			fw, err := w.Encrypt(name, password, enc)
			if err != nil {
				t.Fatal(err)
			}
			fw.Write(files[name])
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range r.File {
			rc, err := zipcrypt.Open(f, password)
			if err != nil {
				t.Fatalf("yeka method %d %s: %v", enc, f.Name, err)
			}
			got, err := io.ReadAll(rc)
			rc.Close()
			if err != nil || !bytes.Equal(got, files[f.Name]) {
				t.Errorf("yeka method %d %s: read differs (err %v)", enc, f.Name, err)
			}
		}
	}
}

// TestWriteSamples writes the sample archives and their source files for
// check.sh. It only runs with ZIPCRYPT_SAMPLES set to an output directory.
func TestWriteSamples(t *testing.T) {
	dir := os.Getenv("ZIPCRYPT_SAMPLES")
	if dir == "" {
		t.Skip("ZIPCRYPT_SAMPLES is not set")
	}
	files := testFiles()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(src, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range samples {
		f, err := os.Create(filepath.Join(dir, s.name))
		if err != nil {
			t.Fatal(err)
		}
		write(t, f, s.method, s.opt, files)
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// TestBigEntries writes and reads back one 4.5 GiB entry per encryption
// method, which needs ZIP64. It only runs with ZIPCRYPT_BIG set to a
// directory, and leaves the archives there for other tools.
func TestBigEntries(t *testing.T) {
	dir := os.Getenv("ZIPCRYPT_BIG")
	if dir == "" {
		t.Skip("ZIPCRYPT_BIG is not set")
	}
	const size = 4608 << 20
	for _, s := range []struct {
		name string
		m    zipcrypt.Method
	}{
		{"big-zc.zip", zipcrypt.ZipCrypto},
		{"big-aes.zip", zipcrypt.AES256},
	} {
		path := filepath.Join(dir, s.name)
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		w := zipcrypt.NewWriter(f)
		fw, err := w.CreateWith(&zip.FileHeader{Name: "big.bin", Method: zip.Deflate, Modified: time.Now()},
			zipcrypt.Options{Method: s.m, Password: password, NoCompression: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(fw, io.LimitReader(zeroReader{}, size)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		f.Close()

		r, err := zip.OpenReader(path)
		if err != nil {
			t.Fatal(err)
		}
		rc, err := zipcrypt.Open(r.File[0], password)
		if err != nil {
			t.Fatal(err)
		}
		n, err := io.Copy(io.Discard, rc)
		rc.Close()
		r.Close()
		if err != nil || n != size {
			t.Errorf("%s: read %d bytes, err %v", s.name, n, err)
		}
	}
}
