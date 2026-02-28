//go:build unit

package middleware

import "context"

// Keep upstream test file unchanged; satisfy UserRepository extension in a sidecar test file.
func (s *stubUserRepo) SetBalance(ctx context.Context, id int64, balance float64) error {
	panic("unexpected SetBalance call")
}
