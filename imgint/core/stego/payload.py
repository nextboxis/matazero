"""Forensic Steganography Payload Extraction, Injection, and Decryption Engine."""

from __future__ import annotations
import os
import struct
import io
import logging
from pathlib import Path
from typing import Optional, Tuple, Union, Dict, Any

import numpy as np
from PIL import Image

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from imgint.core.crypto.ciphers import MATA_CONTAINER_MAGIC, AesImageCipher

logger = logging.getLogger(__name__)

LSB_MAGIC = b"MATA_LSB\x01"  # 9 bytes header


class LsbStego:
    """Least Significant Bit (LSB) steganographic carrier injector and extractor."""

    @classmethod
    def _derive_key(cls, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=50_000,
            backend=default_backend(),
        )
        return kdf.derive(password.encode("utf-8"))

    @classmethod
    def inject(
        cls,
        image: str | Path | Image.Image,
        message: str | bytes,
        output_path: Optional[str | Path] = None,
        password: Optional[str] = None,
        bits_per_channel: int = 1,
    ) -> Union[int, Image.Image]:
        """Injects a payload into the image LSBs with optional AES-256-GCM encryption.
        
        If output_path is provided, saves to disk and returns total bytes embedded.
        If output_path is None, returns the PIL Image with embedded payload.
        """
        if isinstance(image, Image.Image):
            img = image.convert("RGB")
        else:
            img = Image.open(image).convert("RGB")
        arr = np.array(img)
        h, w, c = arr.shape
        capacity_bits = h * w * c * bits_per_channel
        capacity_bytes = capacity_bits // 8

        payload_bytes = message.encode("utf-8") if isinstance(message, str) else message

        flags = 0
        if password:
            flags |= 0x01
            salt = os.urandom(16)
            iv = os.urandom(12)
            key = cls._derive_key(password, salt)
            aesgcm = AESGCM(key)
            encrypted = aesgcm.encrypt(iv, payload_bytes, None)
            body = salt + iv + encrypted
            payload_len = len(payload_bytes)
        else:
            body = payload_bytes
            payload_len = len(payload_bytes)

        # Header: MAGIC (9B) | Flags (1B) | PayloadLen (4B) | Body
        packet = LSB_MAGIC + bytes([flags]) + struct.pack(">I", payload_len) + body
        if len(packet) > capacity_bytes:
            raise ValueError(
                f"Payload size ({len(packet)} bytes) exceeds image LSB capacity ({capacity_bytes} bytes)."
            )

        # Convert packet to bit array
        packet_bits = np.unpackbits(np.frombuffer(packet, dtype=np.uint8))
        flat_arr = arr.reshape(-1)

        if bits_per_channel == 1:
            flat_arr[: len(packet_bits)] = (flat_arr[: len(packet_bits)] & 0xFE) | packet_bits
        elif bits_per_channel == 2:
            pass  # Standard 1 bpc preferred for maximum forensic subtlety
        else:
            raise ValueError("Only 1 bit per channel is currently supported for LSB injection.")

        out_img = Image.fromarray(flat_arr.reshape((h, w, c)), mode="RGB")
        if output_path:
            out_img.save(output_path, format="PNG")
            return len(packet)
        return out_img

    @classmethod
    def extract(
        cls,
        image: str | Path | Image.Image,
        password: Optional[str] = None,
    ) -> Tuple[Optional[bytes], Dict[str, Any]]:
        """Extracts and optionally decrypts an embedded LSB payload."""
        if isinstance(image, Image.Image):
            img = image.convert("RGB")
        else:
            img = Image.open(image).convert("RGB")
        arr = np.array(img)
        flat_arr = arr.reshape(-1)

        # Extract bitstream from plane 0
        bits = flat_arr & 1
        # Pack to bytes
        num_bytes = len(bits) // 8
        raw_extracted = np.packbits(bits[: num_bytes * 8]).tobytes()


        meta: Dict[str, Any] = {
            "has_mata_header": False,
            "is_encrypted": False,
            "extracted_length": 0,
            "recovered_text": None,
        }

        # Check for MATA_LSB header
        if raw_extracted.startswith(LSB_MAGIC):
            meta["has_mata_header"] = True
            offset = len(LSB_MAGIC)
            flags = raw_extracted[offset]
            offset += 1
            is_enc = bool(flags & 0x01)
            meta["is_encrypted"] = is_enc

            (payload_len,) = struct.unpack(">I", raw_extracted[offset : offset + 4])
            offset += 4
            meta["extracted_length"] = payload_len

            if is_enc:
                if not password:
                    raise ValueError(
                        f"Embedded payload is encrypted with AES-256-GCM. Passkey required to decrypt."
                    )
                salt = raw_extracted[offset : offset + 16]
                offset += 16
                iv = raw_extracted[offset : offset + 12]
                offset += 12
                # Ciphertext length is payload_len + 16 (tag)
                ciphertext = raw_extracted[offset : offset + payload_len + 16]

                key = cls._derive_key(password, salt)
                aesgcm = AESGCM(key)
                plain = aesgcm.decrypt(iv, ciphertext, None)
                try:
                    meta["recovered_text"] = plain.decode("utf-8")
                except UnicodeDecodeError:
                    pass
                return plain, meta
            else:
                plain = raw_extracted[offset : offset + payload_len]
                try:
                    meta["recovered_text"] = plain.decode("utf-8")
                except UnicodeDecodeError:
                    pass
                return plain, meta

        # Fallback: scan for readable null-terminated ASCII/UTF-8 string in first 4096 bytes
        sample = raw_extracted[:4096]
        null_idx = sample.find(b"\x00")
        if null_idx > 4:
            cand = sample[:null_idx]
            try:
                text = cand.decode("utf-8")
                if text.isprintable():
                    meta["recovered_text"] = text
                    meta["extracted_length"] = len(cand)
                    return cand, meta
            except UnicodeDecodeError:
                pass

        return None, meta


class TrailingPayload:
    """Carves, decrypts, and extracts payloads appended past JPEG EOI or PNG IEND markers."""

    @classmethod
    def carve(cls, file_path: str | Path) -> Tuple[Optional[bytes], int]:
        """Extracts trailing bytes past standard container termination markers."""
        p = Path(file_path)
        data = p.read_bytes()

        # JPEG EOI is \xFF\xD9
        if data.startswith(b"\xFF\xD8"):
            eoi_idx = data.rfind(b"\xFF\xD9")
            if eoi_idx != -1 and eoi_idx + 2 < len(data):
                trailing = data[eoi_idx + 2 :]
                return trailing, eoi_idx + 2

        # PNG IEND is IEND + 4 bytes CRC
        if data.startswith(b"\x89PNG"):
            iend_idx = data.rfind(b"IEND")
            if iend_idx != -1 and iend_idx + 8 < len(data):
                trailing = data[iend_idx + 8 :]
                return trailing, iend_idx + 8

        return None, -1

    @classmethod
    def extract_and_decrypt(
        cls, file_path: str | Path, password: Optional[str] = None
    ) -> Tuple[Optional[bytes], Dict[str, Any]]:
        """Carves trailing payload and decrypts if encrypted."""
        trailing, offset = cls.carve(file_path)
        if not trailing:
            return None, {"found": False}

        meta: Dict[str, Any] = {
            "found": True,
            "offset": offset,
            "length": len(trailing),
            "payload_type": "UNKNOWN_BINARY",
            "is_encrypted": False,
        }

        # Check for matazero encrypted container
        if trailing.startswith(MATA_CONTAINER_MAGIC):
            meta["is_encrypted"] = True
            meta["payload_type"] = "MATA_ENCRYPTED_CONTAINER"
            if not password:
                return trailing, meta

            # Decrypt in-memory
            magic_len = len(MATA_CONTAINER_MAGIC)
            salt = trailing[magic_len : magic_len + 16]
            iv = trailing[magic_len + 16 : magic_len + 28]
            ciphertext = trailing[magic_len + 28 :]

            key = AesImageCipher.derive_key(password, salt)
            aesgcm = AESGCM(key)
            decrypted = aesgcm.decrypt(iv, ciphertext, None)
            meta["decrypted_length"] = len(decrypted)
            return decrypted, meta

        # Check for standard archive types
        if trailing.startswith(b"PK\x03\x04"):
            meta["payload_type"] = "ZIP_ARCHIVE"
        elif trailing.startswith(b"7z\xBC\xAF\x27\x1C"):
            meta["payload_type"] = "7Z_ARCHIVE"
        elif trailing.startswith(b"Rar!\x1A\x07"):
            meta["payload_type"] = "RAR_ARCHIVE"
        elif trailing.startswith(b"%PDF"):
            meta["payload_type"] = "PDF_DOCUMENT"

        return trailing, meta

    @classmethod
    def inject(
        cls,
        file_path: str | Path,
        output_path: str | Path,
        payload_data: bytes,
        password: Optional[str] = None,
    ) -> int:
        """Appends payload past container end marker, with optional AES-256-GCM encryption."""
        src_data = Path(file_path).read_bytes()

        if password:
            salt = os.urandom(16)
            iv = os.urandom(12)
            key = AesImageCipher.derive_key(password, salt)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(iv, payload_data, None)
            to_append = MATA_CONTAINER_MAGIC + salt + iv + ciphertext
        else:
            to_append = payload_data

        Path(output_path).write_bytes(src_data + to_append)
        return len(to_append)
