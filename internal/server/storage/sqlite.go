// Package storage holds the Raftel control plane persistence layer.
//
// PoC v0.0.1 uses a single-file SQLite database. v0.1 will move to
// Postgres + event sourcing; the Store interface here is intentionally
// thin so we can swap backends later.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
)

type Store struct {
	db *sql.DB
}

type Domain struct {
	Name        string    `json:"name"`
	Parent      string    `json:"parent,omitempty"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

const schema = `
CREATE TABLE IF NOT EXISTS domains (
  name        TEXT    PRIMARY KEY,
  parent      TEXT    NOT NULL DEFAULT '',
  description TEXT    NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_domains_parent ON domains(parent);
`

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) CreateDomain(ctx context.Context, d Domain) (Domain, error) {
	if d.Name == "" {
		return Domain{}, fmt.Errorf("domain name is required")
	}
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now().UTC()
	}
	if d.Parent == "" {
		if i := strings.LastIndex(d.Name, "."); i > 0 {
			d.Parent = d.Name[:i]
		}
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO domains(name, parent, description, created_at) VALUES (?, ?, ?, ?)`,
		d.Name, d.Parent, d.Description, d.CreatedAt.UnixNano(),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			return Domain{}, ErrAlreadyExists
		}
		return Domain{}, fmt.Errorf("insert domain: %w", err)
	}
	return d, nil
}

func (s *Store) GetDomain(ctx context.Context, name string) (Domain, error) {
	var (
		d            Domain
		createdNanos int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT name, parent, description, created_at FROM domains WHERE name = ?`,
		name,
	).Scan(&d.Name, &d.Parent, &d.Description, &createdNanos)
	if errors.Is(err, sql.ErrNoRows) {
		return Domain{}, ErrNotFound
	}
	if err != nil {
		return Domain{}, fmt.Errorf("query domain: %w", err)
	}
	d.CreatedAt = time.Unix(0, createdNanos).UTC()
	return d, nil
}

func (s *Store) ListDomains(ctx context.Context) ([]Domain, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, parent, description, created_at FROM domains ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("query domains: %w", err)
	}
	defer rows.Close()

	var out []Domain
	for rows.Next() {
		var (
			d            Domain
			createdNanos int64
		)
		if err := rows.Scan(&d.Name, &d.Parent, &d.Description, &createdNanos); err != nil {
			return nil, fmt.Errorf("scan domain: %w", err)
		}
		d.CreatedAt = time.Unix(0, createdNanos).UTC()
		out = append(out, d)
	}
	return out, rows.Err()
}
