"""Tests for the face-embedding BLOB codec.

Pure stdlib, so these run in the current sandbox and verify real behaviour.
"""

from __future__ import annotations

import struct

import pytest

from app.database.codec import (
    EMBEDDING_DIM,
    EMBEDDING_DTYPE,
    EmbeddingCodecError,
    decode_embedding,
    encode_embedding,
    expected_byte_length,
)


def _sample_vector(dim: int = EMBEDDING_DIM) -> list[float]:
    return [(i % 97) / 97.0 for i in range(dim)]


def test_expected_byte_length_is_four_bytes_per_value() -> None:
    assert expected_byte_length(512) == 2048
    assert expected_byte_length(1) == 4


def test_encode_produces_exact_blob_size() -> None:
    blob = encode_embedding(_sample_vector())
    assert isinstance(blob, bytes)
    assert len(blob) == 2048


def test_round_trip_is_bit_exact() -> None:
    """float32 storage must not lose precision relative to float32 itself."""
    original = _sample_vector()
    decoded = decode_embedding(encode_embedding(original))
    assert len(decoded) == EMBEDDING_DIM
    for a, b in zip(original, decoded, strict=True):
        # Compare at float32 resolution, which is the stored precision.
        assert struct.pack("<f", a) == struct.pack("<f", b)


def test_round_trip_preserves_negative_and_zero() -> None:
    vector = [0.0, -0.5, 1.0, -1.0] + [0.25] * (EMBEDDING_DIM - 4)
    decoded = decode_embedding(encode_embedding(vector))
    assert decoded[0] == 0.0
    assert decoded[1] == pytest.approx(-0.5)
    assert decoded[2] == pytest.approx(1.0)
    assert decoded[3] == pytest.approx(-1.0)


def test_encode_rejects_wrong_length() -> None:
    with pytest.raises(EmbeddingCodecError, match="length mismatch"):
        encode_embedding([0.1, 0.2, 0.3])


def test_encode_rejects_non_numeric() -> None:
    bad = _sample_vector()
    bad[0] = "not a float"  # type: ignore[call-overload]
    with pytest.raises(EmbeddingCodecError):
        encode_embedding(bad)


def test_decode_rejects_truncated_blob() -> None:
    blob = encode_embedding(_sample_vector())
    with pytest.raises(EmbeddingCodecError, match="length mismatch"):
        decode_embedding(blob[:-4])


def test_decode_rejects_unknown_dtype() -> None:
    """A model/format change must surface as an error, not silent corruption."""
    blob = encode_embedding(_sample_vector())
    with pytest.raises(EmbeddingCodecError, match="unsupported dtype"):
        decode_embedding(blob, dtype="float64")


def test_decode_rejects_dim_mismatch() -> None:
    blob = encode_embedding(_sample_vector())
    with pytest.raises(EmbeddingCodecError, match="length mismatch"):
        decode_embedding(blob, dim=256)


def test_decode_rejects_non_bytes() -> None:
    with pytest.raises(EmbeddingCodecError, match="bytes-like"):
        decode_embedding("not bytes")  # type: ignore[arg-type]


def test_dtype_constant_is_float32() -> None:
    assert EMBEDDING_DTYPE == "float32"
