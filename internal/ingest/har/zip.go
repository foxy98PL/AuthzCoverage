package har

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"authzcov/internal/model"
)

// Decompression limits for .har.zip input. Vars so tests can lower them.
var (
	maxZipTotal int64 = 2 << 30 // decompressed bytes across all members
	maxZipRatio int64 = 100     // per member decompressed/compressed
)

var errZipLimit = errors.New("decompressed size limit exceeded")

// limitReader counts decompressed bytes as they are read and fails past the
// member ratio cap or the shared total cap. Headers are not trusted for size.
type limitReader struct {
	r     io.Reader
	n     int64  // bytes read from this member
	max   int64  // ratio cap for this member
	total *int64 // shared across members
}

func (l *limitReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.n += int64(n)
	*l.total += int64(n)
	if l.n > l.max || *l.total > maxZipTotal {
		return 0, errZipLimit
	}
	return n, err
}

// ExchangesFromFile streams exchanges from a .har file, or from every .har
// member (sorted by name) of a .zip. mk builds the Options for a source label:
// the file's base name, or "<zipbase>!<member>". Errors carry the label.
func ExchangesFromFile(path string, mk func(label string) Options, st *Stats) iter.Seq2[*model.Exchange, error] {
	return func(yield func(*model.Exchange, error) bool) {
		if strings.HasSuffix(strings.ToLower(path), ".zip") {
			fromZip(path, mk, st, yield)
			return
		}
		f, err := os.Open(path) //nolint:gosec // path is a user-supplied CLI argument
		if err != nil {
			yield(nil, fmt.Errorf("har %s: %w", path, err))
			return
		}
		defer func() { _ = f.Close() }()
		for x, err := range Exchanges(f, mk(filepath.Base(path)), st) {
			if err != nil {
				err = fmt.Errorf("har %s: %w", path, err)
			}
			if !yield(x, err) || err != nil {
				return
			}
		}
	}
}

func fromZip(path string, mk func(string) Options, st *Stats, yield func(*model.Exchange, error) bool) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		yield(nil, fmt.Errorf("har %s: %w", path, err))
		return
	}
	defer func() { _ = zr.Close() }()
	var members []*zip.File
	for _, f := range zr.File {
		if !f.FileInfo().IsDir() && strings.HasSuffix(strings.ToLower(f.Name), ".har") {
			members = append(members, f)
		}
	}
	sort.SliceStable(members, func(i, j int) bool { return members[i].Name < members[j].Name })
	if len(members) == 0 {
		yield(nil, fmt.Errorf("har %s: zip contains no .har members", path))
		return
	}
	var total int64
	for _, m := range members {
		label := filepath.Base(path) + "!" + m.Name
		rc, err := m.Open()
		if err != nil {
			yield(nil, fmt.Errorf("har: %s: %w", label, err))
			return
		}
		// The header's CompressedSize64 is attacker-controlled, so this per-member
		// ratio cap is only a heuristic; the total cap, counted from bytes actually
		// read, is the real bound.
		ratioCap := max(int64(min(m.CompressedSize64, 1<<40)), 1) * maxZipRatio //nolint:gosec // clamped below int64 range
		lr := &limitReader{r: rc, max: ratioCap, total: &total}
		for x, err := range Exchanges(lr, mk(label), st) {
			if err != nil && errors.Is(err, errZipLimit) {
				err = fmt.Errorf("har: %s: %w", label, errZipLimit)
			}
			if !yield(x, err) || err != nil {
				_ = rc.Close()
				return
			}
		}
		_ = rc.Close()
	}
}
