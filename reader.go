package zipcrypt

import (
	"archive/zip"
	"bufio"
	"compress/flate"
	"errors"
	"hash"
	"hash/crc32"
	"io"
)

// Open returns a ReadCloser for the contents of f, decrypting it with password
// if f is encrypted. Unencrypted entries are opened with f.Open and the
// password is ignored.
//
// A wrong password is usually reported as ErrPassword. ZipCrypto checks a
// single byte, so about 1 wrong password in 256 gets past that check; the data
// then fails to decompress or to match its CRC-32 instead. AES entries report
// altered data as ErrAuthentication once the end is read, after the decrypted
// bytes have been returned, as any streaming reader must.
func Open(f *zip.File, password string) (io.ReadCloser, error) {
	if f.Flags&0x1 == 0 {
		return f.Open()
	}
	raw, err := f.OpenRaw()
	if err != nil {
		return nil, err
	}
	// flate reads in small pieces; without a buffer each becomes a read of the
	// underlying file.
	raw = bufio.NewReaderSize(raw, 64<<10)

	method, checkCRC := f.Method, true
	var r io.Reader
	if f.Method == methodAES {
		version, strength, inner, err := parseAESExtra(f.Extra)
		if err != nil {
			return nil, err
		}
		if r, err = newAESReader(raw, int64(f.CompressedSize64), []byte(password), strength); err != nil {
			return nil, err
		}
		method, checkCRC = inner, version == 1 // AE-2 sets the CRC-32 to 0
	} else {
		check := byte(f.CRC32 >> 24)
		if f.Flags&0x8 != 0 { // data descriptor: the CRC-32 was not known up front
			check = byte(f.ModifiedTime >> 8)
		}
		if r, err = newZipCryptoReader(raw, []byte(password), check); err != nil {
			return nil, err
		}
	}

	var rc io.ReadCloser
	switch method {
	case zip.Store:
		rc = io.NopCloser(r)
	case zip.Deflate:
		rc = flate.NewReader(r)
	default:
		return nil, zip.ErrAlgorithm
	}
	if checkCRC {
		rc = &crcReader{rc: rc, h: crc32.NewIEEE(), want: f.CRC32}
	}
	return rc, nil
}

// crcReader reports zip.ErrChecksum at the end if the data does not match.
type crcReader struct {
	rc   io.ReadCloser
	h    hash.Hash32
	want uint32
}

func (c *crcReader) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	c.h.Write(p[:n])
	if errors.Is(err, io.EOF) && c.h.Sum32() != c.want {
		return n, zip.ErrChecksum
	}
	return n, err
}

func (c *crcReader) Close() error { return c.rc.Close() }
