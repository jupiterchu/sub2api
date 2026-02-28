//go:build unit

package service

import "context"

// Keep upstream test file unchanged; satisfy UserRepository extension in a sidecar test file.
func (m *mockUserRepo) SetBalance(context.Context, int64, float64) error { return nil }
