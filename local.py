import argparse
import base64
import hashlib
import io
import logging
import mmap
import os
import sqlite3
import sys
import time


class Stats:
    crcs = 0
    bytes = 0
    empty_files = 0
    exceptions = 0
    files = 0
    hashes = 0
    skipped_files = 0
    skipped_file_hashes = 0
    skipped_hashes = 0


class Report:
    exceptions = []
    empty_files = []


stats = Stats()
report = Report()

# https://www.sqlite.org/c3ref/c_limit_attached.html#sqlitelimitvariablenumber
DEFAULT_FILES_BATCH_SIZE = 999


def hash(m):
    # https://github.com/GoogleCloudPlatform/gsutil/blob/db22c6cf44e4f58a56864f0a6f9bcdf868a3c156/gslib/utils/hashing_helper.py#L376
    md5 = hashlib.md5()

    while True:
        data = m.read()
        if not data:
            break
        md5.update(data)
        stats.bytes += len(data)

    return base64.b64encode(md5.digest()).rstrip(b"\n").decode("utf-8")


def crc(m):
    # https://github.com/GoogleCloudPlatform/gsutil/blob/1df98e8233743fbe2ce1a713aad2dd992edb250a/gslib/commands/hash.py#L165
    crc = crcmod.predefined.Crc("crc-32c")
    while True:
        data = m.read()
        if not data:
            break
        crc.update(data)
        stats.bytes += len(data)

    return base64.b64encode(crc.digest()).rstrip(b"\n").decode("utf-8")


def files(dir):
    try:
        for entry in os.scandir(dir):
            if entry.stat().st_size == 0:
                logging.debug("Skipping empty file: {}".format(entry.path))
                stats.empty_files += 1
                report.empty_files.append(entry.path)
                continue                

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
    logging.debug("Processing file: {}".format(path))

    h = None
    c = None

    with open(path, 'rb') as f:
        with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as m:
            try:
                logging.debug("Hashing {}".format(path))
                m.seek(0)

                start = time.process_time()
                h = hash(m)
                end = time.process_time()
                logging.debug("Hashed {} in {}s".format(path, end - start))

                stats.hashes += 1
            except Exception as e:
                logging.warning("Failed to hash {}: {}".format(path, str(e)))
                stats.exceptions += 1
                report.exceptions.append(e)
                return

            if args.crc:
                try:
                    logging.debug("Crcing {}".format(path))
                    m.seek(0)

                    start = time.process_time()
                    c = crc(m)
                    end = time.process_time()
                    logging.debug("Crced {} in {}s".format(path, end - start))

                    stats.crcs += 1
                except Exception as e:
                    logging.warning("Failed to crc {}: {}".format(path, str(e)))
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
            """INSERT INTO files (path, hash, crc) VALUES (:path, :hash, :crc)""",
            {"path": path, "hash": h, "crc": c},
        )

    logging.info("{} {} {}".format(path, h, c))


def process_batch(batch, args, con, cur):
    new_files = []

    if args.skip_duplicate_files:
        sql = "SELECT path FROM files WHERE path IN ({seq})".format(
            seq=",".join(["?"] * len(batch))
        )

        res = cur.execute(sql, batch)

        duplicate_files = set([row[0] for row in res])
        new_files = list(set(batch) - duplicate_files)

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
        if len(files_batch) >= args.batch_size:
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
    parser.add_argument(
        "--batch-size", type=int, default=DEFAULT_FILES_BATCH_SIZE
    )
    parser.add_argument("--crc", action=argparse.BooleanOptionalAction)

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

    if args.crc:
        import crcmod

    con = sqlite3.connect(args.database)
    cur = con.cursor()

    # Create the database.
    cur.execute(
        """
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  path TEXT NOT NULL,
  hash VARCHAR(24),
  crc VARCHAR(8),
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);"""
    )
    con.commit()

    for directory in args.directories:
        process_directory(directory, args, con, cur)

    con.close()

    if args.summary:
        logging.info(
            "{} files, {} hashes, {} crcs, {} exceptions, {} bytes, {}"
            " skipped_files, {} skipped_hashes, {} skipped_file_hashes, {} empty_files"
            .format(
                stats.files,
                stats.hashes,
                stats.crcs,
                stats.exceptions,
                stats.bytes,
                stats.skipped_files,
                stats.skipped_hashes,
                stats.skipped_file_hashes,
                stats.empty_files
            )
        )

    if args.report:
        if len(report.exceptions) > 0:
            logging.info("exceptions: {}".format(report.exceptions))
            logging.info("empty_files: {}".format(report.empty_files))
