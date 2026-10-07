package store

// modernc.org/sqlite is a pure-Go SQLite, so Sherlock builds for Windows
// without cgo or a C compiler.
import _ "modernc.org/sqlite"

const driverName = "sqlite"
