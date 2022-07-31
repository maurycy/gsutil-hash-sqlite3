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
    skipped_file_hashes = 0
    skipped_hashes = 0


class Report:
    exceptions = []


stats = Stats()
report = Report()

# https://www.sqlite.org/c3ref/c_limit_attached.html#sqlitelimitvariablenumber
DEFAULT_FILES_BATCH_SIZE = 999


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
    try:
        for entry in os.scandir(dir):
            if entry.is_file():
                yield entry.path
            elif entry.is_dir():
                yield from files(entry.path)
            else:
                logging.warning("Unknown entry type: {}".format(entry.path))
                continue
    except Exception as e:
        logging.warning("Failed to scandir {}: {}".format(dir, str(e)))
        stats.exceptions += 1
        report.exceptions.append(e)
        return


def process_one(path, args, con, cur):
    h = None

    try:
        h = hash(path)
    except Exception as e:
        logging.warning("Failed to hash {}: {}".format(path, str(e)))
        stats.exceptions += 1
        report.exceptions.append(e)
        return

    if args.skip_duplicate_file_hashes:
        cur.execute(
            "SELECT id FROM files WHERE path = :path AND hash = :hash",
            {"path": path, "hash": h},
        )
        if cur.fetchone():
            logging.debug("Skipping duplicate file hash: {}".format(h))
            stats.skipped_file_hashes += 1
            return

    with con:
        cur.execute(
            """INSERT INTO files (path, hash) VALUES (:path, :hash)""",
            {"path": path, "hash": hash(path)},
        )

    stats.hashes += 1
    logging.info("{} {}".format(path, h))


def process_batch(batch, args, con, cur):
    new_files = []

    if args.skip_duplicate_files:
        sql = "SELECT path FROM files WHERE path IN ({seq})".format(
            seq=",".join(["?"] * len(batch))
        )

        res = cur.execute(sql, batch)

        duplicate_files = [row[0] for row in res]
        new_files = list(set(batch) - set(duplicate_files))

        if len(duplicate_files) > 0:
            logging.debug(
                "Skipping duplicate file: {}".format(duplicate_files)
            )
            stats.skipped_files += len(duplicate_files)

        new_files = new_files
    else:
        new_files = batch

    for path in new_files:
        process_one(path, args, con, cur)


def process_directory(directory, args, con, cur):
    files_batch = []

    for path in files(os.path.abspath(directory)):
        logging.debug(path)
        stats.files += 1

        files_batch.append(path)
        if len(files_batch) >= DEFAULT_FILES_BATCH_SIZE:
            process_batch(files_batch, args, con, cur)
            files_batch = []

    if len(files_batch) > 0:
        process_batch(files_batch, args, con, cur)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "directories", metavar="directory", type=str, nargs="+"
    )
    parser.add_argument("--database", type=str, default="db.sqlite3")
    parser.add_argument("--verbose", action=argparse.BooleanOptionalAction)
    parser.add_argument("--summary", action=argparse.BooleanOptionalAction)
    parser.add_argument("--report", action=argparse.BooleanOptionalAction)
    parser.add_argument(
        "--skip-duplicate-files", action=argparse.BooleanOptionalAction
    )
    parser.add_argument(
        "--skip-duplicate-file-hashes", action=argparse.BooleanOptionalAction
    )

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(
            stream=sys.stdout,
            format="%(levelname)s %(asctime)s - %(message)s",
            level="DEBUG",
            force=True,
        )
    else:
        logging.basicConfig(
            stream=sys.stdout,
            format="%(levelname)s %(asctime)s - %(message)s",
            level="INFO",
        )

    con = sqlite3.connect(args.database)
    cur = con.cursor()

    # Create the database.
    cur.execute(
        """
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  path TEXT NOT NULL,
  hash VARCHAR(24) NOT NULL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);"""
    )
    con.commit()

    for directory in args.directories:
        process_directory(directory, args, con, cur)

    con.close()

    if args.summary:
        logging.info(
            "{} files, {} hashes, {} exceptions {} bytes {} skipped_files {}"
            " skipped_hashes {} skipped_file_hashes".format(
                stats.files,
                stats.hashes,
                stats.exceptions,
                stats.bytes,
                stats.skipped_files,
                stats.skipped_hashes,
                stats.skipped_file_hashes,
            )
        )

    if args.report:
        if len(report.exceptions) > 0:
            logging.info("exceptions: {}".format(report.exceptions))
