# Third-party notices

Original NX Sync Server code is GPLv3-or-later. Dependencies retain their own
licenses. The following notices are distributed with every binary archive.

| Component | Pinned version | License | Full notice |
| --- | --- | --- | --- |
| Go compiler/runtime and standard library | build toolchain 1.26.8; module minimum 1.26 | BSD-3-Clause and patent grant | `third_party/licenses/go.txt`, `go-PATENTS.txt` |
| github.com/ncruces/go-sqlite3 | v0.35.6 | MIT | `third_party/licenses/go-sqlite3.txt` |
| github.com/ncruces/go-sqlite3-wasm/v6 | v6.3.35304 | MIT-0 for original translation support; translated upstream code retains its licenses | `third_party/licenses/go-sqlite3-wasm.txt` |
| SQLite | translation embedded by the pinned module above | SQLite public-domain dedication | [SQLite copyright](https://sqlite.org/copyright.html) |
| SQLite parser (bundled module, including corresponding source) | bundled in v6.3.35304 | MIT | `third_party/licenses/sqlite-parser.txt` |
| github.com/ncruces/julianday | v1.0.0 | MIT | `third_party/licenses/julianday.txt` |
| golang.org/x/sys | v0.48.0 | BSD-3-Clause | `third_party/licenses/golang-x-sys.txt` |

Exact dependency hashes are recorded in go.sum. The build's source archive
contains the project and vendored dependency source, including their original
notices. Build tools are not claimed to be included in the binary archives.
Review this inventory when changing dependencies or the toolchain.
