"""Regression test for the MUTF-8 DEX string reader.

DEX string data is MUTF-8 and NUL-terminated. Its ULEB128 prefix is the UTF-16
code-unit count, not a byte length. A reader that uses the prefix as a byte
length truncates every non-ASCII string, so obfuscated (e.g. CJK) class names
fail to resolve. See DEX.get_string.
"""
import unittest

from dex_fixture import make_mutf8_dex, make_string_dex, mutf8
from droidasc.asc_core.utils.tinydex import DEX

CJK_DESCRIPTOR = 'Lexample/例;'


class Mutf8StringTests(unittest.TestCase):
    def setUp(self):
        self.dex = DEX.parse(memoryview(make_mutf8_dex()), 'mutf8.dex')

    def test_get_string_returns_full_non_ascii_name(self):
        # String index 0 is the CJK class descriptor: 11 UTF-16 units, 13 bytes.
        # The reader must return the whole name, not a byte-truncated prefix.
        self.assertEqual(self.dex.get_string(0), CJK_DESCRIPTOR)

    def test_get_class_resolves_non_ascii_descriptor(self):
        clazz = self.dex.get_class(CJK_DESCRIPTOR)
        self.assertIsNotNone(clazz)
        self.assertEqual(clazz.fullname, CJK_DESCRIPTOR)

    def test_decodes_encoded_null(self):
        value = 'a\0¢'
        dex = DEX.parse(memoryview(make_string_dex(mutf8(value), 3)))
        self.assertEqual(dex.get_string(0), value)

    def test_decodes_empty_string(self):
        dex = DEX.parse(memoryview(make_string_dex(b'', 0)))
        self.assertEqual(dex.get_string(0), '')

    def test_decodes_supplementary_character(self):
        descriptor = 'Lexample/' + chr(0x1f600) + ';'
        dex = DEX.parse(memoryview(make_mutf8_dex(descriptor)), 'supplementary.dex')
        self.assertEqual(dex.get_string(0), descriptor)
        self.assertIsNotNone(dex.get_class(descriptor))

    def test_preserves_unpaired_surrogates(self):
        value = '\ud800x\udc00'
        dex = DEX.parse(memoryview(make_string_dex(mutf8(value), 3)))
        self.assertEqual(dex.get_string(0), value)

    def test_rejects_invalid_string_data(self):
        cases = (
            ('shorter than declared', b'a', 2, True),
            ('longer than declared', b'ab', 1, True),
            ('missing terminator', b'a', 1, False),
            ('truncated sequence', b'\xe1\x80', 1, True),
            ('bad continuation', b'\xe1A\x80', 1, True),
            ('unexpected continuation', b'\x80', 1, True),
            ('overlong encoding', b'\xc1\x81', 1, True),
            ('overlong three-byte encoding', b'\xe0\x80\x80', 1, True),
            ('four-byte UTF-8', chr(0x1f600).encode('utf-8'), 2, True),
        )
        for name, data, utf16_size, terminated in cases:
            with self.subTest(name=name), self.assertRaises(ValueError):
                dex = DEX.parse(memoryview(make_string_dex(data, utf16_size, terminated)))
                dex.get_string(0)


if __name__ == '__main__':
    unittest.main()
