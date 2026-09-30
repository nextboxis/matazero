"""Comprehensive tests for forensic crypto, steganography, detection, and dictionary cracking."""

from __future__ import annotations
import io
import os
import pytest
import numpy as np
from PIL import Image

from imgint.core.crypto.ciphers import (
    cyrb128,
    Mulberry32Cipher,
    AesImageCipher,
    ArnoldCatMapCipher,
    MATA_CONTAINER_MAGIC,
)
from imgint.core.crypto.detector import EncryptionDetector
from imgint.core.crypto.cracker import DictionaryCracker
from imgint.core.stego.payload import LsbStego, TrailingPayload


@pytest.fixture
def sample_rgb_image():
    """Create a smooth gradient natural-like RGB test image."""
    arr = np.zeros((128, 128, 3), dtype=np.uint8)
    for y in range(128):
        for x in range(128):
            arr[y, x, 0] = (x * 2) % 256
            arr[y, x, 1] = (y * 2) % 256
            arr[y, x, 2] = ((x + y)) % 256
    return Image.fromarray(arr, mode="RGB")


@pytest.fixture
def sample_rgba_image():
    """Create a smooth gradient RGBA test image."""
    arr = np.zeros((64, 64, 4), dtype=np.uint8)
    for y in range(64):
        for x in range(64):
            arr[y, x, 0] = (x * 3) % 256
            arr[y, x, 1] = (y * 3) % 256
            arr[y, x, 2] = (x + y) % 256
            arr[y, x, 3] = 255
    return Image.fromarray(arr, mode="RGBA")


class TestMulberry32:
    def test_cyrb128_deterministic(self):
        seeds1 = cyrb128("testkey123")
        seeds2 = cyrb128("testkey123")
        assert len(seeds1) == 4
        assert seeds1 == seeds2
        assert isinstance(seeds1[0], int)

    def test_encrypt_decrypt_roundtrip_rgb(self, sample_rgb_image):
        key = "Secr3tP@ssw0rd"
        encrypted = Mulberry32Cipher.encrypt(sample_rgb_image, key)
        assert encrypted.size == sample_rgb_image.size
        # The encrypted image pixels should differ significantly
        orig_arr = np.array(sample_rgb_image)
        enc_arr = np.array(encrypted)
        assert not np.array_equal(orig_arr, enc_arr)

        decrypted = Mulberry32Cipher.decrypt(encrypted, key)
        assert decrypted.size == sample_rgb_image.size
        dec_arr = np.array(decrypted)
        assert np.array_equal(orig_arr, dec_arr)

    def test_encrypt_decrypt_roundtrip_rgba(self, sample_rgba_image):
        key = "AlphaKey42"
        encrypted = Mulberry32Cipher.encrypt(sample_rgba_image, key)
        assert encrypted.mode == "RGBA"
        # Alpha should remain untouched
        assert np.array_equal(np.array(encrypted)[..., 3], np.array(sample_rgba_image)[..., 3])

        decrypted = Mulberry32Cipher.decrypt(encrypted, key)
        assert np.array_equal(np.array(sample_rgba_image), np.array(decrypted))


class TestAesImageCipher:
    def test_container_gcm_roundtrip(self, tmp_path, sample_rgb_image):
        in_path = tmp_path / "test.png"
        sample_rgb_image.save(in_path)

        enc_path = tmp_path / "test.mataenc"
        dec_path = tmp_path / "test_dec.png"

        key = "HighEntropyForensicKey!2026"
        AesImageCipher.encrypt_file(in_path, enc_path, key)

        with open(enc_path, "rb") as f:
            header = f.read(9)
            assert header == MATA_CONTAINER_MAGIC

        AesImageCipher.decrypt_file(enc_path, dec_path, key)
        dec_img = Image.open(dec_path)
        assert dec_img.size == sample_rgb_image.size
        assert np.array_equal(np.array(sample_rgb_image), np.array(dec_img))

    def test_container_wrong_password_fails(self, tmp_path, sample_rgb_image):
        in_path = tmp_path / "orig.png"
        sample_rgb_image.save(in_path)
        enc_path = tmp_path / "orig.mataenc"
        dec_path = tmp_path / "fail.png"

        AesImageCipher.encrypt_file(in_path, enc_path, "correct_pass")
        with pytest.raises(Exception):
            AesImageCipher.decrypt_file(enc_path, dec_path, "wrong_pass")

    def test_pixel_aes_roundtrip(self, sample_rgb_image):
        key = "PixelAESPassword_123"
        enc_img, meta = AesImageCipher.encrypt_pixels(sample_rgb_image, key, mode="gcm")
        assert enc_img.size == sample_rgb_image.size
        assert "salt" in meta and "iv" in meta

        dec_img = AesImageCipher.decrypt_pixels(enc_img, key, meta)
        assert np.array_equal(np.array(sample_rgb_image), np.array(dec_img))


class TestArnoldCatMap:
    def test_cat_map_roundtrip_square(self, sample_rgb_image):
        rounds = 3
        enc = ArnoldCatMapCipher.encrypt(sample_rgb_image, iterations=rounds)
        assert not np.array_equal(np.array(sample_rgb_image), np.array(enc))

        dec = ArnoldCatMapCipher.decrypt(enc, iterations=rounds)
        assert np.array_equal(np.array(sample_rgb_image), np.array(dec))

    def test_cat_map_roundtrip_nonsquare(self):
        # 60x80 image
        arr = np.random.randint(0, 255, (60, 80, 3), dtype=np.uint8)
        img = Image.fromarray(arr, mode="RGB")
        rounds = 2
        enc = ArnoldCatMapCipher.encrypt(img, iterations=rounds)
        dec = ArnoldCatMapCipher.decrypt(enc, iterations=rounds, original_size=img.size)
        assert np.array_equal(np.array(img), np.array(dec))



class TestEncryptionDetector:
    def test_detect_natural_image(self, sample_rgb_image):
        res = EncryptionDetector.detect_image(sample_rgb_image)
        assert not res["is_encrypted"]
        assert res["gradient_diff"] < 35.0

    def test_detect_encrypted_image(self, sample_rgb_image):
        enc = Mulberry32Cipher.encrypt(sample_rgb_image, "test_scramble_key")
        res = EncryptionDetector.detect_image(enc)
        assert res["is_encrypted"]
        assert res["gradient_diff"] > 50.0

    def test_detect_file_container(self, tmp_path, sample_rgb_image):
        in_path = tmp_path / "img.png"
        sample_rgb_image.save(in_path)
        enc_path = tmp_path / "img.mataenc"
        AesImageCipher.encrypt_file(in_path, enc_path, "ForensicKey")

        res = EncryptionDetector.analyze_file(enc_path)
        assert res.is_encrypted
        assert res.cipher_hint == "AES_CONTAINER"


class TestStegoPayload:
    def test_lsb_plaintext_roundtrip(self, sample_rgb_image):
        msg = b"FORENSIC_EVIDENCE_ID_987654321"
        stego_img = LsbStego.inject(sample_rgb_image, msg)
        extracted, meta = LsbStego.extract(stego_img)
        assert extracted == msg

    def test_lsb_encrypted_roundtrip(self, sample_rgb_image):
        msg = b"CONFIDENTIAL_INTELLIGENCE_REPORT_TOP_SECRET"
        passkey = "StegoVaultKey!777"
        stego_img = LsbStego.inject(sample_rgb_image, msg, password=passkey)

        with pytest.raises(Exception):
            LsbStego.extract(stego_img, password="WrongPassword")

        extracted, meta = LsbStego.extract(stego_img, password=passkey)
        assert extracted == msg

    def test_trailing_payload_roundtrip(self, tmp_path, sample_rgb_image):
        img_path = tmp_path / "carrier.png"
        out_path = tmp_path / "carrier_injected.png"
        sample_rgb_image.save(img_path, format="PNG")

        secret_data = b"Carved_Evidence_Payload_Binary_Bytes"
        passkey = "TrailingSecret#123"

        TrailingPayload.inject(img_path, out_path, secret_data, password=passkey)

        extracted, meta = TrailingPayload.extract_and_decrypt(out_path, password=passkey)
        assert extracted == secret_data
        assert meta["is_encrypted"] is True


class TestDictionaryCracker:
    def test_cracker_finds_password(self, tmp_path, sample_rgb_image):
        true_password = "cyberforensics"
        enc_img = Mulberry32Cipher.encrypt(sample_rgb_image, true_password)
        img_path = tmp_path / "enc_test.png"
        enc_img.save(img_path)

        candidates = ["wrong1", "admin123", "password", "cyberforensics", "qwerty"]
        res = DictionaryCracker.crack(img_path, extra_candidates=candidates)

        assert res is not None
        matched_pwd, best_diff = res
        assert matched_pwd == true_password
        assert best_diff < 35.0
