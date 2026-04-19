import unittest

from pwn.payloads import cyclic


class CyclicTests(unittest.TestCase):
    def test_cyclic_matches_linux_pwntools_prefix(self):
        expected = (
            b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaaf"
        )
        self.assertEqual(cyclic(512), expected)

    def test_cyclic_rejects_lengths_beyond_sequence_space(self):
        with self.assertRaises(ValueError):
            cyclic((26**4) + 1)


if __name__ == "__main__":
    unittest.main()
