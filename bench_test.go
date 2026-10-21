package zipcrypt

import (
	"archive/zip"
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
