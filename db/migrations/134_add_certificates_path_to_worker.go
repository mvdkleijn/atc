package migrations

import "github.com/concourse/atc/dbng/migration"

func AddCertificatesPathToWorkers(tx migration.LimitedTx) error {
	_, err := tx.Exec(`
		ALTER TABLE workers
		ADD COLUMN certificates_path text;
`)
	return err
}
