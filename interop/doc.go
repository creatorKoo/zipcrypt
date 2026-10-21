// Package interop checks zipcrypt against other ZIP implementations.
//
// It is a separate module so that zipcrypt itself has no dependencies. The
// tests read and write archives with github.com/yeka/zip, an independent
// implementation of both encryption methods, and check.sh runs Info-ZIP
// unzip, Python's zipfile, libarchive's bsdtar and 7-Zip on archives that
// zipcrypt wrote.
package interop
