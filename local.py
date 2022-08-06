import argparse
import logging
import mmap
import os
import sqlite3
import sys
import time

import hash.dropbox_content_hash
import hash.crc32
import hash.md5


class Stats:
    crcs = 0
    bytes = 0
    dropbox_content_hashes = 0
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


def files(dir):
    try:
        for entry in os.scandir(dir):
            if entry.stat().st_size == 0:
                logging.debug("Skipping empty file: {}".format(entry.path))
                stats.empty_files += 1
                report.empty_files.append(entry.path)
                continue

            if entry.is_file():
                ctime = entry.stat().st_ctime if args.ctime else None
                mtime = entry.stat().st_mtime if args.mtime else None
                yield entry.path, ctime, mtime
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


def process_one(path, ctime, mtime, args, con, cur):
    logging.debug("Processing file: {}".format(path))

    h = None
    c = None
    d = None

    with open(path, "rb") as f:
        with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as m:
            try:
                logging.debug("Hashing {}".format(path))
                m.seek(0)

                start = time.process_time()
                h, bytes = hash.md5.hash(m)
                end = time.process_time()
                logging.debug("Hashed {} in {}s".format(path, end - start))

                stats.hashes += 1
                stats.bytes += bytes
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
                    c, bytes = hash.crc32.hash(m)
                    end = time.process_time()
                    logging.debug("Crced {} in {}s".format(path, end - start))

                    stats.crcs += 1
                    stats.bytes += bytes
                except Exception as e:
                    logging.warning(
                        "Failed to crc {}: {}".format(path, str(e))
                    )
                    stats.exceptions += 1
                    report.exceptions.append(e)
                    return

            if args.dropbox_content_hash:
                try:
                    logging.debug("Dropbox content hashing {}".format(path))
                    m.seek(0)

                    start = time.process_time()
                    d, bytes = hash.dropbox_content_hash.hash(m)
                    end = time.process_time()
                    logging.debug(
                        "Dropbox content hashed {} in {}s".format(
                            path, end - start
                        )
                    )

                    stats.dropbox_content_hashes += 1
                    stats.bytes += bytes
                except Exception as e:
                    logging.warning(
                        "Failed to dropbox content hash {}: {}".format(
                            path, str(e)
                        )
                    )
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
            """INSERT INTO files (path, hash, crc, dropbox_content_hash, ctime, mtime) VALUES (:path, :hash, :crc, :dropbox_content_hash, :ctime, :mtime)""",
            {
                "path": path,
                "hash": h,
                "crc": c,
                "dropbox_content_hash": d,
                "ctime": ctime,
                "mtime": mtime,
            },
        )

    logging.info("{} {} {} {}".format(path, h, c, d))


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

    for path, mtime, ctime in new_files:
        process_one(path, mtime, ctime, args, con, cur)


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
    parser.add_argument(
        "--crc", action=argparse.BooleanOptionalAction, default=True
    )
    parser.add_argument(
        "--dropbox-content-hash",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    parser.add_argument(
        "--mtime", action=argparse.BooleanOptionalAction, default=True
    )
    parser.add_argument(
        "--ctime", action=argparse.BooleanOptionalAction, default=True
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
  hash VARCHAR(24),
  crc VARCHAR(8),
  dropbox_content_hash VARCHAR(64),
  mtime INTEGER,
  ctime INTEGER,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);"""
    )
    con.commit()

    # Run the migrations.
    try:
        cur.execute(
            """
ALTER TABLE files ADD COLUMN mtime INTEGER;
        """
        )
        con.commit()
    except sqlite3.OperationalError:
        pass

    try:
        cur.execute(
            """
ALTER TABLE files ADD COLUMN ctime INTEGER;
        """
        )
        con.commit()
    except sqlite3.OperationalError:
        pass

    for directory in args.directories:
        process_directory(directory, args, con, cur)

    con.commit()
    con.close()

    if args.summary:
        logging.info(
            "{} files, {} hashes, {} crcs, {} dropbox_content_hashes, {}"
            " exceptions, {} bytes, {} skipped_files, {} skipped_hashes, {}"
            " skipped_file_hashes, {} empty_files".format(
                stats.files,
                stats.hashes,
                stats.crcs,
                stats.dropbox_content_hashes,
                stats.exceptions,
                stats.bytes,
                stats.skipped_files,
                stats.skipped_hashes,
                stats.skipped_file_hashes,
                stats.empty_files,
            )
        )

    if args.report:
        if len(report.exceptions) > 0:
            logging.info("exceptions: {}".format(report.exceptions))
            logging.info("empty_files: {}".format(report.empty_files))
