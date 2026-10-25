// Package raijinscan holds the engine versions this tool was tested with.
package raijinscan

import _ "embed"

// EnginesJSON is engines.json: the engine versions the benchmark fixtures were produced with.
//
//go:embed engines.json
var EnginesJSON []byte
