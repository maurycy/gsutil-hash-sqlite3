import argparse
import base64
import hashlib
import logging
import os
import sqlite3
import sys


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["count"])
    parser.add_argument("--database", type=str, default="db.sqlite3")
    parser.add_argument("--include", dest="substring", type=str)

    args = parser.parse_args()

    logging.basicConfig(
        stream=sys.stdout,
        format="%(levelname)s %(asctime)s - %(message)s",
        level="INFO",
    )

    con = sqlite3.connect(args.database)
    cur = con.cursor()

    match args.command:
        case "count":
            if args.substring:
                res = cur.execute(
                    "SELECT COUNT() FROM files WHERE path LIKE :pattern",
                    {
                        "pattern": "".join(["%", args.substring, "%"]),
                    },
                )
                print(cur.fetchone()[0])
            else:
                res = cur.execute("SELECT COUNT() FROM files")
                print(res.fetchone()[0])

    con.close()
