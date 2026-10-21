// Package zipcrypt adds password protection to archive/zip.
//
// It does not fork archive/zip. Writer wraps a *zip.Writer and registers its
// own compressors on it; for entries created with Writer.CreateWith they
// compress at the requested level and then encrypt. Everything else, such as
// headers, CRC-32, data descriptors, ZIP64 and the central directory, is left
// to archive/zip. Open decrypts entries read with zip.Reader.
//
// Two encryption methods are supported:
//
//   - ZipCrypto, the traditional PKWARE encryption. It is cryptographically
//     weak, but it is the only method that Windows Explorer and macOS Archive
//     Utility open without extra software.
//   - WinZip AES (AE-1) with 128, 192 or 256-bit keys, which 7-Zip, WinZip,
//     WinRAR and similar tools open.
package zipcrypt

import (
	"archive/zip"
	"compress/flate"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
)

// Method selects how an entry is encrypted.
type Method int

const (
	// None writes the entry unencrypted.
	None Method = iota
	// ZipCrypto is the traditional PKWARE encryption. It is weak, but it is
	// the only method Windows Explorer and macOS Archive Utility can open.
	ZipCrypto
	// AES128, AES192 and AES256 are WinZip AES encryption (AE-1). They need
	// 7-Zip, WinZip, WinRAR or a similar tool to open.
	AES128
	AES192
	AES256
)

func (m Method) String() string {
	switch m {
	case None:
		return "None"
	case ZipCrypto:
		return "ZipCrypto"
	case AES128:
		return "AES128"
	case AES192:
		return "AES192"
	case AES256:
		return "AES256"
	}
	return "Method(" + strconv.Itoa(int(m)) + ")"
}

func (m Method) aesStrength() byte {
	switch m {
	case AES128:
		return 1
	case AES192:
		return 2
	case AES256:
		return 3
	}
	return 0
}

// defaultLevel is the flate level archive/zip uses for Deflate entries.
const defaultLevel = 5

// Options describes how one entry is written.
type Options struct {
	// Method selects the encryption. The zero value, None, writes the entry
	// unencrypted.
	Method Method

	// Password encrypts the entry. It is required unless Method is None, and
	// must be empty if Method is None.
	Password string

	// Level is the flate level for Deflate entries, as for flate.NewWriter.
	// Zero means 5, the level archive/zip uses.
	Level int

	// NoCompression writes Deflate entries as uncompressed blocks, for data
	// that is already compressed, such as JPEG or MP4. It is as fast as Store
	// and adds 5 bytes per 64 KiB, but unlike Store the entry ends itself:
	// readers that scan an archive from the front, such as macOS ditto, cannot
	// mistake bytes inside it for the end of the entry.
	NoCompression bool
}

func (o Options) level() int {
	switch {
	case o.NoCompression:
		return flate.NoCompression
	case o.Level == 0:
		return defaultLevel
	}
	return o.Level
}

// Writer is a zip.Writer that can also write encrypted entries. Entries added
// through the embedded zip.Writer are written unencrypted, as archive/zip
// would write them.
type Writer struct {
	*zip.Writer

	next *pending // the entry CreateWith is creating
}

type pending struct {
	fh     *zip.FileHeader
	opt    Options
	method uint16 // compression method under AES (fh.Method is 99)
}

// NewWriter returns a Writer writing a zip file to w.
//
// It registers compressors for zip.Store, zip.Deflate and method 99 (AES) on
// the embedded zip.Writer. Registering another compressor for those methods
// on it disables encryption for them.
func NewWriter(w io.Writer) *Writer {
	x := &Writer{Writer: zip.NewWriter(w)}
	x.RegisterCompressor(zip.Store, x.store)
	x.RegisterCompressor(zip.Deflate, x.deflate)
	x.RegisterCompressor(methodAES, x.aes)
	return x
}

// CreateWith adds a file to the archive like zip.Writer.CreateHeader and
// compresses and encrypts it as opt says. fh.Method must be zip.Store or
// zip.Deflate. Directories are never encrypted. As with CreateHeader, the
// file's contents must be written before the next call to CreateWith,
// CreateHeader or Close, and fh must not be modified or reused afterwards.
func (w *Writer) CreateWith(fh *zip.FileHeader, opt Options) (io.Writer, error) {
	if fh.Method != zip.Store && fh.Method != zip.Deflate {
		return nil, zip.ErrAlgorithm
	}
	switch {
	case opt.Method < None || opt.Method > AES256:
		return nil, errors.New("zipcrypt: unknown encryption method " + opt.Method.String())
	case opt.Method != None && opt.Password == "":
		return nil, errors.New("zipcrypt: " + opt.Method.String() + " needs a password")
	case opt.Method == None && opt.Password != "":
		return nil, errors.New("zipcrypt: a password was given but Method is None")
	}
	p := &pending{fh: fh, opt: opt}
	if opt.Method != None && !strings.HasSuffix(fh.Name, "/") {
		fh.Flags |= 0x1 // encrypted
		if s := opt.Method.aesStrength(); s != 0 {
			p.method = fh.Method
			fh.Method = methodAES
			fh.Extra = append(fh.Extra, aesExtra(s, p.method)...)
		}
	}
	w.next = p
	defer func() { w.next = nil }()
	return w.Writer.CreateHeader(fh)
}

// The compressors below are called by zip.Writer.CreateHeader before it writes
// the local file header, so they must not write anything until the first Write
// or Close. archive/zip has already set fh.ModifiedTime by then, which
// ZipCrypto uses for its check byte.

func (w *Writer) store(out io.Writer) (io.WriteCloser, error) {
	p := w.next
	if p == nil || p.opt.Method != ZipCrypto {
		return nopCloser{out}, nil
	}
	return newZipCryptoWriter(out, []byte(p.opt.Password), byte(p.fh.ModifiedTime>>8))
}

func (w *Writer) deflate(out io.Writer) (io.WriteCloser, error) {
	p := w.next
	if p == nil {
		return newFlateWriter(out, defaultLevel)
	}
	if p.opt.Method != ZipCrypto {
		return newFlateWriter(out, p.opt.level())
	}
	zc, err := newZipCryptoWriter(out, []byte(p.opt.Password), byte(p.fh.ModifiedTime>>8))
	if err != nil {
		return nil, err
	}
	return newDeflateThen(zc, p.opt.level())
}

func (w *Writer) aes(out io.Writer) (io.WriteCloser, error) {
	p := w.next
	if p == nil {
		return nil, errors.New("zipcrypt: AES entries must be created with CreateWith")
	}
	aw, err := newAESWriter(out, []byte(p.opt.Password), p.opt.Method.aesStrength())
	if err != nil {
		return nil, err
	}
	if p.method == zip.Store {
		return aw, nil
	}
	return newDeflateThen(aw, p.opt.level())
}

// deflateThen compresses into an encrypting writer and closes it after the
// compressor, so the last compressed block is encrypted before the
// encryption trailer, if any, is written.
type deflateThen struct {
	fw   io.WriteCloser
	next io.WriteCloser
}

func newDeflateThen(next io.WriteCloser, level int) (*deflateThen, error) {
	fw, err := newFlateWriter(next, level)
	if err != nil {
		return nil, err
	}
	return &deflateThen{fw: fw, next: next}, nil
}

// flatePools holds flate writers by level, indexed from flate.HuffmanOnly.
// Each one allocates close to 1 MB, so archives of many small files would
// otherwise keep the garbage collector busy; archive/zip pools its default
// compressor for the same reason.
var flatePools [flate.BestCompression - flate.HuffmanOnly + 1]sync.Pool

func newFlateWriter(w io.Writer, level int) (io.WriteCloser, error) {
	if level < flate.HuffmanOnly || level > flate.BestCompression {
		return nil, errors.New("zipcrypt: invalid compression level " + strconv.Itoa(level))
	}
	pool := &flatePools[level-flate.HuffmanOnly]
	fw, ok := pool.Get().(*flate.Writer)
	if ok {
		fw.Reset(w)
	} else {
		var err error
		if fw, err = flate.NewWriter(w, level); err != nil {
			return nil, err
		}
	}
	return &pooledFlate{fw: fw, pool: pool}, nil
}

// pooledFlate returns its flate writer to the pool on Close.
type pooledFlate struct {
	fw   *flate.Writer
	pool *sync.Pool
}

func (p *pooledFlate) Write(b []byte) (int, error) {
	if p.fw == nil {
		return 0, errors.New("zipcrypt: write after close")
	}
	return p.fw.Write(b)
}

func (p *pooledFlate) Close() error {
	if p.fw == nil {
		return nil
	}
	err := p.fw.Close()
	p.pool.Put(p.fw)
	p.fw = nil
	return err
}

func (d *deflateThen) Write(p []byte) (int, error) { return d.fw.Write(p) }

func (d *deflateThen) Close() error {
	if err := d.fw.Close(); err != nil {
		return err
	}
	return d.next.Close()
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }
