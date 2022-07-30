import argparse
import base64
import hashlib
import logging
import os
import sqlite3
import sys

parser = argparse.ArgumentParser()
parser.add_argument('directories', metavar='directory', type=str, nargs='+')
parser.add_argument('--database', type=str, default='db.sqlite3')
parser.add_argument('--verbose', action=argparse.BooleanOptionalAction)


def hash(path):
    # https://github.com/GoogleCloudPlatform/gsutil/blob/db22c6cf44e4f58a56864f0a6f9bcdf868a3c156/gslib/utils/hashing_helper.py#L376
    md5 = hashlib.md5()

    with open(path, 'rb') as f:
        while True:
            data = f.read(8192)
            if not data:
                break
            md5.update(data)

    return base64.b64encode(md5.digest()).rstrip(b'\n').decode('utf-8')


def files(dir):
    for entry in os.scandir(dir):
        if entry.is_file():
            yield entry.path
        elif entry.is_dir():
            yield from files(entry.path)
        else:
            logging.warning('Unknown entry type: {}'.format(entry.path))
            continue


if __name__ == '__main__':
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level='DEBUG')

    logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

    con = sqlite3.connect(args.database)
    cur = con.cursor()

    # Create the database.
    cur.execute('''
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  path text NOT NULL,
  hash text NOT NULL
);''')
    con.commit()

    for directory in args.directories:
        for path in files(os.path.abspath(directory)):
            logging.debug(path)

            h = None

            try:
                h = hash(path)
            except Exception as e:
                logging.warning('Failed to hash {}: {}'.format(path, str(e)))
                continue

            cur.execute('''INSERT INTO files (path, hash) VALUES (:path, :hash)''', {
                        'path': path, 'hash': hash(path)})
            con.commit()

            logging.info("{} {}".format(path, h))
