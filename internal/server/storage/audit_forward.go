package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// AuditForwardSeq returns the highest audit_log seq that the named
// forwarder has confirmed delivery for. Zero (the default for a fresh
// row) means "start from the beginning of the chain".
func (s *Store) AuditForwardSeq(ctx context.Context, name string) (int64, error) {
	if name == "" {
		return 0, errors.New("audit forward: name is required")
	}
	var seq int64
	err := s.db.QueryRowContext(ctx,
		s.rebind(`SELECT last_seq FROM audit_forward_state WHERE name = ?`),
		name,
	).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("audit forward: read seq: %w", err)
	}
	return seq, nil
}

// SetAuditForwardSeq atomically advances the watermark for the named
// forwarder. Callers must only invoke it after the receiver has
// acknowledged every event up to and including seq, so a crash between
// forward and SetAuditForwardSeq results in at-least-once redelivery
// (idempotent on the receiver via the event's stable Hash).
//
// `INSERT ... ON CONFLICT(name) DO UPDATE` is supported by both SQLite
// (>= 3.24) and Postgres (>= 9.5), so the same statement works on both
// drivers.
func (s *Store) SetAuditForwardSeq(ctx context.Context, name string, seq int64) error {
	if name == "" {
		return errors.New("audit forward: name is required")
	}
	if seq < 0 {
		return fmt.Errorf("audit forward: seq must be non-negative, got %d", seq)
	}
	_, err := s.db.ExecContext(ctx,
		s.rebind(`INSERT INTO audit_forward_state(name, last_seq, updated_at)
		 VALUES (?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET last_seq = excluded.last_seq, updated_at = excluded.updated_at`),
		name, seq, time.Now().UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("audit forward: write seq: %w", err)
	}
	return nil
}
