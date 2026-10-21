package zipcrypt

import (
	"crypto/rand"
	"errors"
	"hash/crc32"
	"io"
)

// zipCrypto is the traditional PKWARE stream cipher (APPNOTE.TXT section 6.1).
// It is weak and only exists for compatibility: it is the one encryption
// method Windows Explorer and macOS Archive Utility open without extra software.
type zipCrypto struct {
	k0, k1, k2 uint32
}

func newZipCrypto(password []byte) *zipCrypto {
	z := &zipCrypto{0x12345678, 0x23456789, 0x34567890}
	for _, b := range password {
		z.update(b)
	}
	return z
}

func crc32Update(crc uint32, b byte) uint32 {
	return crc>>8 ^ crc32.IEEETable[byte(crc)^b]
}

func (z *zipCrypto) update(b byte) {
	z.k0 = crc32Update(z.k0, b)
	z.k1 = (z.k1+z.k0&0xff)*134775813 + 1
	z.k2 = crc32Update(z.k2, byte(z.k1>>24))
}

func (z *zipCrypto) keystream() byte {
	t := z.k2 | 2
	return byte(t * (t ^ 1) >> 8)
}

// encrypt and decrypt inline update and keystream with the keys in locals;
// this loop runs once per byte and is the bottleneck of ZipCrypto entries.
// dst and src may overlap entirely.
func (z *zipCrypto) encrypt(dst, src []byte) {
	k0, k1, k2 := z.k0, z.k1, z.k2
	tab := crc32.IEEETable
	dst = dst[:len(src)]
	for i, b := range src {
		t := k2 | 2
		dst[i] = b ^ byte(t*(t^1)>>8)
		k0 = k0>>8 ^ tab[byte(k0)^b]
		k1 = (k1+k0&0xff)*134775813 + 1
		k2 = k2>>8 ^ tab[byte(k2)^byte(k1>>24)]
	}
	z.k0, z.k1, z.k2 = k0, k1, k2
}

func (z *zipCrypto) decrypt(dst, src []byte) {
	k0, k1, k2 := z.k0, z.k1, z.k2
	tab := crc32.IEEETable
	dst = dst[:len(src)]
	for i, c := range src {
		t := k2 | 2
		b := c ^ byte(t*(t^1)>>8)
		dst[i] = b
		k0 = k0>>8 ^ tab[byte(k0)^b]
		k1 = (k1+k0&0xff)*134775813 + 1
		k2 = k2>>8 ^ tab[byte(k2)^byte(k1>>24)]
	}
	z.k0, z.k1, z.k2 = k0, k1, k2
}

// zipCryptoHeaderLen is the size of the encryption header that precedes the
// encrypted data. Its last byte lets readers reject a wrong password early.
const zipCryptoHeaderLen = 12

// zipCryptoWriter encrypts everything written to it, preceded by the
// encryption header. Close writes the header if nothing else was written, so
// even an empty entry carries one; it does not close the underlying writer.
type zipCryptoWriter struct {
	w       io.Writer
	z       *zipCrypto
	hdr     [zipCryptoHeaderLen]byte // already encrypted
	started bool
	buf     []byte
}

// newZipCryptoWriter prepares the encryption header. check is the byte
// readers compare against: the high byte of the CRC-32, or, for entries that
// use a data descriptor (as every file written through archive/zip does), the
// high byte of the MS-DOS modification time.
func newZipCryptoWriter(w io.Writer, password []byte, check byte) (*zipCryptoWriter, error) {
	e := &zipCryptoWriter{w: w, z: newZipCrypto(password)}
	if _, err := rand.Read(e.hdr[:zipCryptoHeaderLen-1]); err != nil {
		return nil, err
	}
	e.hdr[zipCryptoHeaderLen-1] = check
	e.z.encrypt(e.hdr[:], e.hdr[:])
	return e, nil
}

// start writes the encryption header. archive/zip creates the compressor
// before it writes the local file header, so nothing may reach w earlier.
func (e *zipCryptoWriter) start() error {
	if e.started {
		return nil
	}
	e.started = true
	_, err := e.w.Write(e.hdr[:])
	return err
}

func (e *zipCryptoWriter) Write(p []byte) (int, error) {
	if err := e.start(); err != nil {
		return 0, err
	}
	if cap(e.buf) < len(p) {
		e.buf = make([]byte, len(p))
	}
	b := e.buf[:len(p)]
	e.z.encrypt(b, p)
	if _, err := e.w.Write(b); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (e *zipCryptoWriter) Close() error { return e.start() }

// ErrPassword is returned when the password does not match an entry.
var ErrPassword = errors.New("zipcrypt: wrong password")

// zipCryptoReader decrypts r after checking the encryption header.
type zipCryptoReader struct {
	r io.Reader
	z *zipCrypto
}

func newZipCryptoReader(r io.Reader, password []byte, check byte) (*zipCryptoReader, error) {
	z := newZipCrypto(password)
	var hdr [zipCryptoHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	z.decrypt(hdr[:], hdr[:])
	if hdr[zipCryptoHeaderLen-1] != check {
		return nil, ErrPassword
	}
	return &zipCryptoReader{r: r, z: z}, nil
}

func (d *zipCryptoReader) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	d.z.decrypt(p[:n], p[:n])
	return n, err
}
