"""Face-embedding BLOB codec.

Encodes a 512-dimensional float32 vector to a little-endian BLOB and back,
validating dimension and dtype on every read so that a model change is
*detected* rather than silently producing meaningless similarity scores
(DATABASE_DESIGN.md section 3.3, SR-STORE-02).

This module is intentionally pure stdlib: no SQLAlchemy, no NumPy, no vision
library. It is storage plumbing only and performs no face processing, so it
does not encroach on the Day 3 face-recognition scope.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence

#: Dimensionality produced by the approved recogniser (InsightFace, 512-D).
EMBEDDING_DIM = 512

#: Only dtype supported on the wire. Stored alongside each row.
EMBEDDING_DTYPE = "float32"

#: Little-endian, explicit so a BLOB written on one host decodes on another.
_BYTE_ORDER = "<"

#: Bytes per float32 value.
_ITEM_SIZE = 4


class EmbeddingCodecError(ValueError):
    """Raised when an embedding cannot be safely encoded or decoded."""


def expected_byte_length(dim: int = EMBEDDING_DIM) -> int:
    """Exact BLOB size for ``dim`` float32 values."""
    return dim * _ITEM_SIZE


def encode_embedding(vector: Sequence[float], *, dim: int = EMBEDDING_DIM) -> bytes:
    """Pack a float sequence into a little-endian float32 BLOB.

    Raises:
        EmbeddingCodecError: if the length is wrong or a value is not a
            finite real number.
    """
    if dim <= 0:
        raise EmbeddingCodecError(f"dim must be positive, got {dim}")

    length = len(vector)
    if length != dim:
        raise EmbeddingCodecError(
            f"embedding length mismatch: expected {dim}, got {length}"
        )

    try:
        return struct.pack(f"{_BYTE_ORDER}{dim}f", *vector)
    except (struct.error, TypeError, OverflowError) as exc:
        raise EmbeddingCodecError(f"cannot encode embedding: {exc}") from exc


def decode_embedding(
    blob: bytes,
    *,
    dim: int = EMBEDDING_DIM,
    dtype: str = EMBEDDING_DTYPE,
) -> list[float]:
    """Unpack a BLOB back into a list of floats.

    ``dim`` and ``dtype`` are the values recorded on the database row. They are
    validated rather than trusted, so a model or format change surfaces as an
    error instead of corrupting comparisons.

    Raises:
        EmbeddingCodecError: on dtype mismatch, wrong byte length, or
            malformed data.
    """
    if dtype != EMBEDDING_DTYPE:
        raise EmbeddingCodecError(
            f"unsupported dtype {dtype!r}: only {EMBEDDING_DTYPE!r} is supported"
        )
    if dim <= 0:
        raise EmbeddingCodecError(f"dim must be positive, got {dim}")
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise EmbeddingCodecError(
            f"embedding blob must be bytes-like, got {type(blob).__name__}"
        )

    expected = expected_byte_length(dim)
    actual = len(blob)
    if actual != expected:
        raise EmbeddingCodecError(
            f"embedding blob length mismatch: expected {expected} bytes "
            f"for dim={dim}, got {actual}"
        )

    try:
        return list(struct.unpack(f"{_BYTE_ORDER}{dim}f", bytes(blob)))
    except struct.error as exc:
        raise EmbeddingCodecError(f"cannot decode embedding: {exc}") from exc
