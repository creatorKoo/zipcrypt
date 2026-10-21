# zipcrypt

[![Go Reference](https://pkg.go.dev/badge/github.com/creatorKoo/zipcrypt.svg)](https://pkg.go.dev/github.com/creatorKoo/zipcrypt)
[![CI](https://github.com/creatorKoo/zipcrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/creatorKoo/zipcrypt/actions/workflows/ci.yml)

Password-protected ZIP archives for Go, on top of the standard `archive/zip`.

```sh
go get github.com/creatorKoo/zipcrypt
```

`archive/zip` cannot encrypt or decrypt, and adding that was proposed and
declined ([golang/go#12081](https://github.com/golang/go/issues/12081)). The
packages that can, such as alexmullins/zip and yeka/zip, are copies of an old
`archive/zip` that no longer receive its fixes.

zipcrypt does not copy `archive/zip`. It wraps a `*zip.Writer` and adds the
encryption layer through `Writer.RegisterCompressor`, so headers, ZIP64 and the
central directory stay with the standard library. It has no dependencies and
needs Go 1.24 or later.

## Writing

```go
w := zipcrypt.NewWriter(out)

fh := &zip.FileHeader{Name: "report.pdf", Method: zip.Deflate}
fh.SetMode(0o644)
fw, err := w.CreateWith(fh, zipcrypt.Options{
	Method:   zipcrypt.AES256,
	Password: "secret",
})
if err != nil {
	return err
}
if _, err := io.Copy(fw, report); err != nil {
	return err
}

return w.Close()
```

`Writer` embeds the `*zip.Writer`. Entries added through it (`w.Create`,
`w.CreateHeader`) are written unencrypted, exactly as `archive/zip` writes them.

## Reading

```go
r, err := zip.OpenReader("archive.zip")
if err != nil {
	return err
}
defer r.Close()
for _, f := range r.File {
	rc, err := zipcrypt.Open(f, "secret") // unencrypted entries open as with f.Open
	if err != nil {
		return err
	}
	// read rc, then
	rc.Close()
}
```

## Encryption methods

| Method | Supported by | Notes |
|---|---|---|
| `ZipCrypto` | Windows Explorer, macOS Archive Utility and practically every ZIP tool | Weak: it falls to known-plaintext attacks. Use it when the recipient cannot install anything. |
| `AES128`, `AES192`, `AES256` | 7-Zip, WinZip, WinRAR, libarchive and others | WinZip AES, AE-1 format |

## Options

- `Level` is the flate level for Deflate entries. Zero means 5, the level
  `archive/zip` uses.
- `NoCompression` writes Deflate entries as uncompressed blocks, for files that
  are already compressed, such as JPEG, MP4 or ZIP. It is as fast as Store, but
  unlike Store the entry ends itself, so readers that scan an archive from the
  front, such as macOS `ditto`, cannot cut it short at a stray signature inside
  the data.

## Compatibility

CI checks archives written by zipcrypt with Info-ZIP unzip, Python's `zipfile`,
libarchive (`bsdtar`), 7-Zip and yeka/zip, and checks that zipcrypt reads what
yeka/zip writes. See [interop](interop).

Things to know:

- AES entries use AE-1, which keeps the CRC-32 of the plain data. AE-2 sets it
  to 0 so that it cannot leak information about small files, but `archive/zip`
  always writes the CRC-32, so zipcrypt cannot produce AE-2. `Open` reads both.
- Call `FileHeader.SetMode`, or build the header with `zip.FileInfoHeader`.
  Without it `archive/zip` records MS-DOS as the creating system, and some Unix
  tools, such as Info-ZIP unzip on macOS, then decode non-ASCII names as an old
  DOS code page.
- `Open` returns decrypted data as it reads. Altered AES data is reported as
  `ErrAuthentication` at the end, after the bytes have been returned.

## Performance

Writing one 64 MiB entry as uncompressed Deflate blocks on an Apple silicon Mac
(`go test -bench .`):

| Method | Throughput |
|---|---|
| None | 8.5 GB/s |
| AES256 | 1.1 GB/s |
| ZipCrypto | 0.5 GB/s |

ZipCrypto has to process one byte at a time.

## License

MIT
