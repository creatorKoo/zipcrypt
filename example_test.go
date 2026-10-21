package zipcrypt_test

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"log"

	"github.com/creatorKoo/zipcrypt"
)

func Example() {
	// Write an archive with one AES-256 encrypted file.
	var buf bytes.Buffer
	w := zipcrypt.NewWriter(&buf)
	fw, err := w.CreateWith(&zip.FileHeader{Name: "secret.txt", Method: zip.Deflate},
		zipcrypt.Options{Method: zipcrypt.AES256, Password: "golang"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprint(fw, "Hello, Gophers!")
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}

	// Read it back with archive/zip and zipcrypt.Open.
	r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		log.Fatal(err)
	}
	rc, err := zipcrypt.Open(r.File[0], "golang")
	if err != nil {
		log.Fatal(err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(b))
	// Output: Hello, Gophers!
}

// Files that are already compressed, such as photos and videos, gain almost
// nothing from Deflate. NoCompression writes them at disk speed.
func ExampleOptions_noCompression() {
	var buf bytes.Buffer
	w := zipcrypt.NewWriter(&buf)
	fw, err := w.CreateWith(&zip.FileHeader{Name: "photo.jpg", Method: zip.Deflate},
		zipcrypt.Options{Method: zipcrypt.ZipCrypto, Password: "golang", NoCompression: true})
	if err != nil {
		log.Fatal(err)
	}
	fw.Write([]byte{0xff, 0xd8, 0xff, 0xe0}) // the JPEG data
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}
}
