import argparse
import base64
import hashlib
import io
import logging
import os
import sqlite3
import sys


class Stats:
    bytes = 0
    exceptions = 0
    files = 0
    hashes = 0
    skipped_files = 0
    skipped_hashes = 0


stats = Stats()


def hash(path):
    # https://github.com/GoogleCloudPlatform/gsutil/blob/db22c6cf44e4f58a56864f0a6f9bcdf868a3c156/gslib/utils/hashing_helper.py#L376
    md5 = hashlib.md5()

    with open(path, "rb") as f:
        while True:
            data = f.read(io.DEFAULT_BUFFER_SIZE)
            if not data:
                break
            md5.update(data)
            stats.bytes += len(data)

    return base64.b64encode(md5.digest()).rstrip(b"\n").decode("utf-8")


def files(dir):
    for entry in os.scandir(dir):
        if entry.is_file():
            yield entry.path
        elif entry.is_dir():
            yield from files(entry.path)
        else:
            logging.warning("Unknown entry type: {}".format(entry.path))
            continue


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "directories", metavar="directory", type=str, nargs="+"
    )
    parser.add_argument("--database", type=str, default="db.sqlite3")
    parser.add_argument("--verbose", action=argparse.BooleanOptionalAction)
    parser.add_argument("--summary", action=argparse.BooleanOptionalAction)
    parser.add_argument(
        "--skip-duplicate-files", action=argparse.BooleanOptionalAction
    )
    parser.add_argument(
        "--skip-duplicate-hashes", action=argparse.BooleanOptionalAction
    )

    args = parser.parse_args()

    logging.basicConfig(
        stream=sys.stdout,
        format="%(levelname)s %(asctime)s - %(message)s",
        level="INFO",
    )

    if args.verbose:
        logging.basicConfig(
            stream=sys.stdout,
            format="%(levelname)s %(asctime)s - %(message)s",
            level="DEBUG",
            force=True,
        )

    con = sqlite3.connect(args.database)
    cur = con.cursor()

    # Create the database.
    cur.execute(
        """
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  path text NOT NULL,
  hash text NOT NULL
);"""
    )
    con.commit()

    for directory in args.directories:
        for path in files(os.path.abspath(directory)):
            logging.debug(path)
            stats.files += 1

            if args.skip_duplicate_files:
                cur.execute(
                    "SELECT hash FROM files WHERE path = :path",
                    {"path": path},
                )
                if cur.fetchone():
                    logging.debug("Skipping duplicate file: {}".format(path))
                    stats.skipped_files += 1
                    continue

            h = None

            try:
                h = hash(path)
            except Exception as e:
                logging.warning("Failed to hash {}: {}".format(path, str(e)))
                stats.exceptions += 1
                continue

            if args.skip_duplicate_hashes:
                cur.execute(
                    "SELECT id FROM files WHERE hash = :hash", {"hash": h}
                )
                if cur.fetchone():
                    logging.debug("Skipping duplicate hash: {}".format(h))
                    stats.skipped_hashes += 1
                    continue

            cur.execute(
                """INSERT INTO files (path, hash) VALUES (:path, :hash)""",
                {"path": path, "hash": hash(path)},
            )
            con.commit()

            stats.hashes += 1
            logging.info("{} {}".format(path, h))

    con.close()

    if args.summary:
        logging.info(
            "{} files, {} hashes, {} exceptions {} bytes {} skipped_files {}"
            " skipped_hashes".format(
                stats.files,
                stats.hashes,
                stats.exceptions,
                stats.bytes,
                stats.skipped_files,
                stats.skipped_hashes,
            )
        )
