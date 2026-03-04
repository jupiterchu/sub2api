//go:build unit

package handler

import (
	"context"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// Keep upstream test file unchanged; satisfy UserRepository extension in a sidecar test file.
func (r *stubUserRepoForHandler) SetBalance(_ context.Context, id int64, balance float64) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	u, ok := r.users[id]
	if !ok {
		return service.ErrUserNotFound
	}
	u.Balance = balance
	r.users[id] = u
	return nil
}
