import base64
import io

import crcmod

DESCRIPTION = "Base64-encoded CRC-32C"


def hash(m):
    # https://github.com/GoogleCloudPlatform/gsutil/blob/1df98e8233743fbe2ce1a713aad2dd992edb250a/gslib/commands/hash.py#L165
    crc = crcmod.predefined.Crc("crc-32c")

    bytes = 0

    while True:
        data = m.read(io.DEFAULT_BUFFER_SIZE)
        if not data:
            break
        crc.update(data)
        bytes += len(data)

    return (
        base64.b64encode(crc.digest()).rstrip(b"\n").decode("utf-8"),
        bytes,
    )
