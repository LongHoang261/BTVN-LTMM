import unittest
from aes_tables import S_BOX, INV_S_BOX, RCON, nhan_gf
from aes import (
    ma_hoa_aes_128, giai_ma_aes_128,
    ma_hoa_aes_128_chi_tiet, tron_cot, tron_cot_nguoc,
    bytes_sang_state, state_sang_bytes
)


class TestAES(unittest.TestCase):
    def test_bang_va_gf(self):
        self.assertEqual(nhan_gf(0x57, 0x83), 0xC1)
        self.assertEqual(nhan_gf(0xA6, 0x3D), 0xC6)
        self.assertEqual([S_BOX[x] for x in (0, 1, 2, 0x53, 0xFF)],
                         [0x63, 0x7C, 0x77, 0xED, 0x16])
        for x in range(256):
            self.assertEqual(INV_S_BOX[S_BOX[x]], x)
        self.assertEqual(RCON[1:11],
                         [1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36])

    def test_state_va_mix_columns(self):
        du_lieu = list(range(16))
        self.assertEqual(state_sang_bytes(bytes_sang_state(du_lieu)), du_lieu)

        state = [[0xD4, 0, 0, 0], [0xBF, 0, 0, 0],
                 [0x5D, 0, 0, 0], [0x30, 0, 0, 0]]
        tron_cot(state)
        self.assertEqual([state[i][0] for i in range(4)], [4, 0x66, 0x81, 0xE5])
        tron_cot_nguoc(state)
        self.assertEqual([state[i][0] for i in range(4)], [0xD4, 0xBF, 0x5D, 0x30])

    def test_ma_hoa_giai_ma(self):
        cac_vi_du = [
            ("0f1571c947d9e8590cb7add6af7f6798",
             "0123456789abcdeffedcba9876543210",
             "ff0b844a0853bf7c6934ab4364148fb9"),
            ("2b7e151628aed2a6abf7158809cf4f3c",
             "3243f6a8885a308d313198a2e0370734",
             "3925841d02dc09fbdc118597196a0b32"),
            ("00" * 16, "00" * 16,
             "66e94bd4ef8a2c3b884cfa59ca342b2e")
        ]
        for khoa, ban_ro, ban_ma_chuan in cac_vi_du:
            with self.subTest(khoa=khoa):
                ban_ma = ma_hoa_aes_128(ban_ro, khoa)
                self.assertEqual(ban_ma.lower(), ban_ma_chuan)
                self.assertEqual(giai_ma_aes_128(ban_ma, khoa).lower(), ban_ro)

    def test_in_trang_thai(self):
        khoa = "0f1571c947d9e8590cb7add6af7f6798"
        ban_ro = "0123456789abcdeffedcba9876543210"
        ban_ma, log = ma_hoa_aes_128_chi_tiet(ban_ro, khoa)
        self.assertEqual(ban_ma, "FF0B844A0853BF7C6934AB4364148FB9")
        self.assertIn("Vong 10", log)


if __name__ == "__main__":
    unittest.main(verbosity=2)
