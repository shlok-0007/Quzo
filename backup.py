"""Create and validate a Quzo database backup without overwriting an existing file."""

import argparse
import os
import sqlite3
import subprocess
from contextlib import closing
from pathlib import Path
from tempfile import NamedTemporaryFile

from sqlalchemy.engine import make_url


def _verify_sqlite(connection):
    if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
        raise ValueError("SQLite integrity check failed.")
    if not connection.execute("SELECT 1 FROM sqlite_master WHERE name = 'quiz'").fetchone():
        raise ValueError("Backup is missing Quzo's quiz table.")


def backup_database(database_url, destination):
    """Write an inspected backup archive and publish it only on success."""

    target = Path(destination).resolve()
    if target.exists():
        raise FileExistsError("Backup destination already exists.")
    url = make_url(database_url)
    with NamedTemporaryFile(prefix=".quzo-backup-", dir=target.parent, delete=False) as temporary:
        staged = Path(temporary.name)
    try:
        if url.get_backend_name() == "sqlite":
            if not url.database or url.database == ":memory:":
                raise ValueError("Use a file-backed SQLite database.")
            source_path = Path(url.database).resolve().as_uri()
            with closing(sqlite3.connect(source_path + "?mode=ro", uri=True)) as source:
                with closing(sqlite3.connect(staged)) as archive:
                    source.backup(archive)
                    _verify_sqlite(archive)
        elif url.get_backend_name() == "postgresql":
            connection = url.set(drivername="postgresql").render_as_string(hide_password=False)
            env = dict(os.environ, PGDATABASE=connection)
            subprocess.run(
                ["pg_dump", "--no-password", "--format=custom", f"--file={staged}"],
                env=env, check=True,
            )
            subprocess.run(
                ["pg_restore", "--list", str(staged)], stdout=subprocess.DEVNULL, check=True,
            )
        else:
            raise ValueError("Quzo backup supports SQLite and PostgreSQL.")
        os.link(staged, target)  # Atomic publish and fail if another process already wrote it.
    finally:
        staged.unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", help="New output file in an existing private directory.")
    args = parser.parse_args()
    source = os.environ.get("QUZO_BACKUP_DATABASE_URL")
    if not source:
        parser.error("Set QUZO_BACKUP_DATABASE_URL in the backup process environment.")
    backup_database(source, args.destination)
