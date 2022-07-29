import argparse
import re
import sqlite3

parser = argparse.ArgumentParser()
parser.add_argument('file', metavar='file', type=str)
parser.add_argument('--database', type=str, default='db.sqlite3')

if __name__ == '__main__':
    args = parser.parse_args()

    con = sqlite3.connect(args.database)
    cur = con.cursor()

    # Create the database.
    cur.execute('''
CREATE TABLE urls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url text NOT NULL
);''')

    cur.execute('''
CREATE TABLE details (
  url_id INTEGER NOT NULL,
  key text NOT NULL,
  value text NOT NULL,
  FOREIGN KEY(url_id) REFERENCES urls(id)
)
''')
    con.commit()

    with open(args.file, 'r') as f:
        url = None
        url_id = None

        for line in f:
            line = line.strip()

            if line.startswith('gs://'):
                # Remove the trailing :
                url = line[:-1]

                cur.execute(
                    'INSERT INTO urls (url) VALUES (:url)', {'url': url})
                con.commit()

                url_id = cur.lastrowid
            else:
                assert url != None
                assert url_id != None

                chunks = line.split(':')
                key = chunks[0].strip()
                value = ''.join(chunks[1:]).strip()

                if not value:
                    assert key == 'Metadata'
                    continue

                if url is not None:
                    cur.execute('''INSERT INTO details (url_id, key, value) VALUES (:url_id, :key, :value)''', {
                                'url_id': url_id, 'key': key, 'value': value})
