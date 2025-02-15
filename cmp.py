import argparse
import collections
import logging
import sqlite3
import sys


# https://stackoverflow.com/a/48359027
def namedtuple_factory(cursor, row):
    """Returns sqlite rows as named tuples."""
    fields = [col[0] for col in cursor.description]
    Row = collections.namedtuple("Row", fields)
    return Row(*row)


def diff(target, source):
    # Create the database.
    cur.execute(
        """
SELECT
    *
FROM files
WHERE
    path LIKE '{}%' AND
    crc IN (
        SELECT DISTINCT crc FROM files WHERE path LIKE '{}%' 
        EXCEPT
        SELECT DISTINCT crc FROM files WHERE path LIKE '{}%'
    )
""".format(args.source, args.source, args.target)
    )
    for row in cur.fetchall():
        yield row


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=str)
    parser.add_argument("source", type=str)
    parser.add_argument("--database", type=str, default="db.sqlite3")
    parser.add_argument("--verbose", action=argparse.BooleanOptionalAction)

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
    # con.row_factory = namedtuple_factory
    cur = con.cursor()

    for row in diff(args.target, args.source):
        logging.info(" ".join(map(str, row)))
    for row in diff(args.source, args.target):
        logging.info(" ".join(map(str, row)))

    con.close()
