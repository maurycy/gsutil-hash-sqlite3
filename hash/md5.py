import hashlib
import io
import base64

DESCRIPTION = "Base64-encoded MD5 hash"


def hash(m):
    # https://github.com/GoogleCloudPlatform/gsutil/blob/db22c6cf44e4f58a56864f0a6f9bcdf868a3c156/gslib/utils/hashing_helper.py#L376
    md5 = hashlib.md5()

    bytes = 0

    while True:
        data = m.read(io.DEFAULT_BUFFER_SIZE)
        if not data:
            break
        md5.update(data)
        bytes += len(data)

    return (
        base64.b64encode(md5.digest()).rstrip(b"\n").decode("utf-8"),
        bytes,
    )
