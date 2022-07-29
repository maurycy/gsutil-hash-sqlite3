import argparse
import base64
import hashlib
import os
import sqlite3

parser = argparse.ArgumentParser()
parser.add_argument('directory', metavar='directory', type=str)
parser.add_argument('--database', type=str, default='db.sqlite3')


def hash(path):
    # https://github.com/GoogleCloudPlatform/gsutil/blob/db22c6cf44e4f58a56864f0a6f9bcdf868a3c156/gslib/utils/hashing_helper.py#L376
    # .encode('base64').strip()
    return base64.b64encode(hashlib.md5(open(path, 'rb').read()).digest()).decode('ascii')


def files(dir):
    for entry in os.scandir(dir):
        if entry.is_file():
            yield entry.path
        elif entry.is_dir():
            yield from files(entry.path)
        else:
            # raise Exception('Unknown entry type: {}'.format(entry.path))
            continue


if __name__ == '__main__':
    args = parser.parse_args()

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

    for path in files(os.path.abspath(args.directory)):
      cur.execute('''INSERT INTO files (path, hash) VALUES (:path, :hash)''', {
                  'path': path, 'hash': hash(path)})
      con.commit()
