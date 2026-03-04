//go:build unit

package service

import "context"

// Keep upstream test file unchanged; satisfy UserRepository extension in a sidecar test file.
func (r *stubUserRepoForQuota) SetBalance(_ context.Context, id int64, balance float64) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	u, ok := r.users[id]
	if !ok {
		return ErrUserNotFound
	}
	u.Balance = balance
	r.users[id] = u
	return nil
}
