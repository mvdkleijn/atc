package migrations

import "github.com/concourse/atc/dbng/migration"

func AddAuthToTeams(tx migration.LimitedTx) error {
	_, err := tx.Exec(`
    ALTER TABLE teams
    ADD COLUMN auth json null;
	`)
	return err
}
