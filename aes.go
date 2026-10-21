package zipcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
)

// WinZip AES encryption (https://www.winzip.com/en/support/aes-encryption/).
// The entry's method is 99 and an extra field records the AES strength and
// the real compression method. The data is salt, a 2-byte password verifier,
// the AES-CTR ciphertext and a 10-byte HMAC-SHA1 authentication code.
const (
	methodAES  = 99
	aesExtraID = 0x9901
	aesMACLen  = 10
	aesPWVLen  = 2

	// aesVendorVersion is AE-1, which keeps the CRC-32 of the plain data.
	// archive/zip always computes and writes that CRC, so AE-2 (CRC set to 0)
	// is not possible on top of it.
	aesVendorVersion = 1
)

// ErrAuthentication is returned at the end of an AES entry whose data does not
// match its authentication code.
var ErrAuthentication = errors.New("zipcrypt: authentication failed")

// aesKeyLen returns the key size for a strength code (1, 2 or 3).
func aesKeyLen(strength byte) int {
	return 8 + 8*int(strength)
}

// aesKeys derives the AES key, the HMAC key and the password verifier.
func aesKeys(password, salt []byte, keyLen int) (cipher.Block, hash.Hash, []byte, error) {
	dk, err := pbkdf2.Key(sha1.New, string(password), salt, 1000, 2*keyLen+aesPWVLen)
	if err != nil {
		return nil, nil, nil, err
	}
	block, err := aes.NewCipher(dk[:keyLen])
	if err != nil {
		return nil, nil, nil, err
	}
	return block, hmac.New(sha1.New, dk[keyLen:2*keyLen]), dk[2*keyLen:], nil
}

// ctrLE is AES in CTR mode with a little-endian counter starting at 1, as
// WinZip uses. crypto/cipher's CTR counts big-endian.
type ctrLE struct {
	b    cipher.Block
	ctr  [aes.BlockSize]byte
	ks   [aes.BlockSize]byte
	used int
}

func newCTRLE(b cipher.Block) *ctrLE {
	return &ctrLE{b: b, used: aes.BlockSize}
}

func (c *ctrLE) XORKeyStream(dst, src []byte) {
	for len(src) > 0 {
		if c.used == aes.BlockSize {
			for i := range c.ctr {
				c.ctr[i]++
				if c.ctr[i] != 0 {
					break
				}
			}
			c.b.Encrypt(c.ks[:], c.ctr[:])
			c.used = 0
		}
		n := subtle.XORBytes(dst, src, c.ks[c.used:])
		dst, src = dst[n:], src[n:]
		c.used += n
	}
}

// aesExtra builds the extra field of an AES entry.
func aesExtra(strength byte, method uint16) []byte {
	b := make([]byte, 11)
	binary.LittleEndian.PutUint16(b[0:], aesExtraID)
	binary.LittleEndian.PutUint16(b[2:], 7)
	binary.LittleEndian.PutUint16(b[4:], aesVendorVersion)
	b[6], b[7] = 'A', 'E'
	b[8] = strength
	binary.LittleEndian.PutUint16(b[9:], method)
	return b
}

// parseAESExtra finds the AES extra field in extra.
func parseAESExtra(extra []byte) (version uint16, strength byte, method uint16, err error) {
	for len(extra) >= 4 {
		id := binary.LittleEndian.Uint16(extra[0:])
		size := int(binary.LittleEndian.Uint16(extra[2:]))
		if len(extra) < 4+size {
			break
		}
		if id == aesExtraID && size >= 7 {
			d := extra[4 : 4+size]
			version, strength, method = binary.LittleEndian.Uint16(d[0:]), d[4], binary.LittleEndian.Uint16(d[5:])
			if d[2] != 'A' || d[3] != 'E' || strength < 1 || strength > 3 {
				return 0, 0, 0, fmt.Errorf("zipcrypt: unsupported AES extra field")
			}
			return version, strength, method, nil
		}
		extra = extra[4+size:]
	}
	return 0, 0, 0, errors.New("zipcrypt: AES extra field not found")
}

// aesWriter encrypts and authenticates everything written to it, preceded by
// the salt and the password verifier. Close writes the authentication code; it
// does not close the underlying writer.
type aesWriter struct {
	w      io.Writer
	prefix []byte // salt and password verifier, until they are written
	ctr    *ctrLE
	mac    hash.Hash
	buf    []byte
}

func newAESWriter(w io.Writer, password []byte, strength byte) (*aesWriter, error) {
	keyLen := aesKeyLen(strength)
	salt := make([]byte, keyLen/2)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	block, mac, pwv, err := aesKeys(password, salt, keyLen)
	if err != nil {
		return nil, err
	}
	return &aesWriter{w: w, prefix: append(salt, pwv...), ctr: newCTRLE(block), mac: mac}, nil
}

// start writes the salt and the password verifier. archive/zip creates the
// compressor before it writes the local file header, so nothing may reach w
// earlier.
func (a *aesWriter) start() error {
	if a.prefix == nil {
		return nil
	}
	p := a.prefix
	a.prefix = nil
	_, err := a.w.Write(p)
	return err
}

func (a *aesWriter) Write(p []byte) (int, error) {
	if err := a.start(); err != nil {
		return 0, err
	}
	if cap(a.buf) < len(p) {
		a.buf = make([]byte, len(p))
	}
	b := a.buf[:len(p)]
	a.ctr.XORKeyStream(b, p)
	a.mac.Write(b)
	if _, err := a.w.Write(b); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (a *aesWriter) Close() error {
	if err := a.start(); err != nil {
		return err
	}
	_, err := a.w.Write(a.mac.Sum(nil)[:aesMACLen])
	return err
}

// aesReader decrypts an AES entry. The authentication code is checked when
// the ciphertext runs out, so callers see ErrAuthentication instead of io.EOF
// if the data was altered; like every streaming reader, it hands out the
// decrypted bytes before that check.
type aesReader struct {
	r    io.Reader // ciphertext only
	raw  io.Reader // ciphertext followed by the authentication code
	ctr  *ctrLE
	mac  hash.Hash
	done bool // the authentication code has been checked
}

func newAESReader(raw io.Reader, size int64, password []byte, strength byte) (*aesReader, error) {
	keyLen := aesKeyLen(strength)
	saltPWV := make([]byte, keyLen/2+aesPWVLen)
	if _, err := io.ReadFull(raw, saltPWV); err != nil {
		return nil, err
	}
	salt, pwv := saltPWV[:keyLen/2], saltPWV[keyLen/2:]
	block, mac, want, err := aesKeys(password, salt, keyLen)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(pwv, want) != 1 {
		return nil, ErrPassword
	}
	n := size - int64(len(saltPWV)) - aesMACLen
	if n < 0 {
		return nil, errors.New("zipcrypt: AES entry too short")
	}
	return &aesReader{r: io.LimitReader(raw, n), raw: raw, ctr: newCTRLE(block), mac: mac}, nil
}

func (a *aesReader) Read(p []byte) (int, error) {
	if a.done {
		return 0, io.EOF
	}
	n, err := a.r.Read(p)
	a.mac.Write(p[:n])
	a.ctr.XORKeyStream(p[:n], p[:n])
	if err == io.EOF {
		a.done = true
		var code [aesMACLen]byte
		if _, rerr := io.ReadFull(a.raw, code[:]); rerr != nil {
			return n, rerr
		}
		if !hmac.Equal(code[:], a.mac.Sum(nil)[:aesMACLen]) {
			return n, ErrAuthentication
		}
	}
	return n, err
}
