package zipcrypt

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
)

// BenchmarkWrite measures writing one 64 MiB entry stored as uncompressed
// Deflate blocks, with each encryption method.
func BenchmarkWrite(b *testing.B) {
	data := make([]byte, 64<<20)
	rand.Read(data)
	for _, m := range []Method{None, ZipCrypto, AES256} {
		b.Run(fmt.Sprintf("method%d", m), func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for range b.N {
				w := NewWriter(io.Discard)
				fw, err := w.CreateWith(&zip.FileHeader{Name: "a.mp4", Method: zip.Deflate},
					Options{Method: m, Password: password(m), NoCompression: true})
				if err != nil {
					b.Fatal(err)
				}
				fw.Write(data)
				w.Close()
			}
		})
	}
}

// BenchmarkManySmallEntries writes 1000 small Deflate entries, where creating
// a flate writer per entry dominates.
func BenchmarkManySmallEntries(b *testing.B) {
	data := bytes.Repeat([]byte("small file "), 100)
	b.ReportAllocs()
	for range b.N {
		w := NewWriter(io.Discard)
		for i := range 1000 {
			fw, err := w.CreateWith(&zip.FileHeader{Name: fmt.Sprint(i), Method: zip.Deflate}, Options{})
			if err != nil {
				b.Fatal(err)
			}
			fw.Write(data)
		}
		w.Close()
	}
}
