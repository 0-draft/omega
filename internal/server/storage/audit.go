package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// AuditEvent is one entry in the tamper-evident audit chain.
//
// Each row's Hash covers (Seq, Ts, Kind, Actor, Subject, Decision, Payload,
// PrevHash). PrevHash references the previous row's Hash, so any tampering
// with an earlier row invalidates every subsequent Hash.
type AuditEvent struct {
	Seq      int64           `json:"seq"`
	Ts       time.Time       `json:"ts"`
	Kind     string          `json:"kind"`
	Actor    string          `json:"actor,omitempty"`
	Subject  string          `json:"subject,omitempty"`
	Decision string          `json:"decision,omitempty"`
	Payload  json.RawMessage `json:"payload,omitempty"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
}

const genesisHash = "GENESIS"

// auditMu serialises Append calls so the prev_hash lookup and INSERT
// happen atomically. SQLite's BEGIN IMMEDIATE would also serialise, but
// a process-local mutex keeps the contention error-free.
//
// NOTE: this mutex is process-local. Multi-replica Postgres deployments
// need an external leader-election layer before two writers can be
// active concurrently - otherwise interleaved INSERTs can break the
// hash chain. Single-writer SQLite and single-writer Postgres are fine.
var auditMu sync.Mutex

// AppendAudit writes one event to the chain. Seq, Ts, PrevHash and Hash are
// computed by the store; callers fill the rest. The stored event is
// returned, including the assigned Seq and Hash.
func (s *Store) AppendAudit(ctx context.Context, ev AuditEvent) (AuditEvent, error) {
	if !s.IsLeader() {
		return AuditEvent{}, ErrNotLeader
	}
	if ev.Kind == "" {
		return AuditEvent{}, errors.New("audit: kind is required")
	}
	if ev.Ts.IsZero() {
		ev.Ts = time.Now().UTC()
	}
	if ev.Payload == nil {
		ev.Payload = json.RawMessage("{}")
	}

	auditMu.Lock()
	defer auditMu.Unlock()

	prev, err := s.lastAuditHash(ctx)
	if err != nil {
		return AuditEvent{}, err
	}
	ev.PrevHash = prev

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuditEvent{}, fmt.Errorf("audit: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// `INSERT ... RETURNING seq` works on both SQLite (>= 3.35) and
	// Postgres, so we avoid driver-specific LastInsertId() (which lib/pq
	// does not support for serial columns).
	var seq int64
	insertSQL := s.rebind(
		`INSERT INTO audit_log(ts, kind, actor, subject, decision, payload, prev_hash, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING seq`,
	)
	if err := tx.QueryRowContext(ctx, insertSQL,
		ev.Ts.UnixNano(), ev.Kind, ev.Actor, ev.Subject, ev.Decision,
		string(ev.Payload), ev.PrevHash, "pending",
	).Scan(&seq); err != nil {
		return AuditEvent{}, fmt.Errorf("audit: insert: %w", err)
	}
	ev.Seq = seq
	ev.Hash = hashAuditEvent(ev)

	if _, err := tx.ExecContext(ctx,
		s.rebind(`UPDATE audit_log SET hash = ? WHERE seq = ?`),
		ev.Hash, seq,
	); err != nil {
		return AuditEvent{}, fmt.Errorf("audit: update hash: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return AuditEvent{}, fmt.Errorf("audit: commit: %w", err)
	}
	return ev, nil
}

func (s *Store) lastAuditHash(ctx context.Context) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx,
		`SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`,
	).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return genesisHash, nil
	}
	if err != nil {
		return "", fmt.Errorf("audit: last hash: %w", err)
	}
	return hash, nil
}

// ListAudit returns events with Seq > since, oldest first, capped at limit.
// limit <= 0 defaults to 100; values above 1000 are clamped.
func (s *Store) ListAudit(ctx context.Context, since int64, limit int) ([]AuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.QueryContext(ctx,
		s.rebind(
			`SELECT seq, ts, kind, actor, subject, decision, payload, prev_hash, hash
			 FROM audit_log WHERE seq > ? ORDER BY seq ASC LIMIT ?`,
		),
		since, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	defer rows.Close()

	out := make([]AuditEvent, 0, limit)
	for rows.Next() {
		var (
			ev      AuditEvent
			tsNanos int64
			payload string
		)
		if err := rows.Scan(&ev.Seq, &tsNanos, &ev.Kind, &ev.Actor, &ev.Subject,
			&ev.Decision, &payload, &ev.PrevHash, &ev.Hash); err != nil {
			return nil, fmt.Errorf("audit: scan: %w", err)
		}
		ev.Ts = time.Unix(0, tsNanos).UTC()
		ev.Payload = json.RawMessage(payload)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// VerifyAudit walks the entire chain. Returns the seq of the first row
// whose hash does not match its computed value, or 0 if the chain is intact.
func (s *Store) VerifyAudit(ctx context.Context) (firstBadSeq int64, err error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, ts, kind, actor, subject, decision, payload, prev_hash, hash
		 FROM audit_log ORDER BY seq ASC`,
	)
	if err != nil {
		return 0, fmt.Errorf("audit: verify query: %w", err)
	}
	defer rows.Close()

	prev := genesisHash
	for rows.Next() {
		var (
			ev      AuditEvent
			tsNanos int64
			payload string
		)
		if err := rows.Scan(&ev.Seq, &tsNanos, &ev.Kind, &ev.Actor, &ev.Subject,
			&ev.Decision, &payload, &ev.PrevHash, &ev.Hash); err != nil {
			return 0, fmt.Errorf("audit: verify scan: %w", err)
		}
		ev.Ts = time.Unix(0, tsNanos).UTC()
		ev.Payload = json.RawMessage(payload)
		if ev.PrevHash != prev {
			return ev.Seq, nil
		}
		if hashAuditEvent(ev) != ev.Hash {
			return ev.Seq, nil
		}
		prev = ev.Hash
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("audit: verify rows: %w", err)
	}
	return 0, nil
}

func hashAuditEvent(ev AuditEvent) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d|%d|%s|%s|%s|%s|", ev.Seq, ev.Ts.UnixNano(), ev.Kind, ev.Actor, ev.Subject, ev.Decision)
	h.Write([]byte(ev.Payload))
	h.Write([]byte("|"))
	h.Write([]byte(ev.PrevHash))
	return hex.EncodeToString(h.Sum(nil))
}
