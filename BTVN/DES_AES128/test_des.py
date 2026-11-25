import unittest
from des import (
    sinh_khoa_con, bit_sang_hex, ma_hoa_khoi_des, giai_ma_khoi_des,
    ma_hoa_khoi_des_chi_tiet, kiem_tra_parity_le
)


class TestDES(unittest.TestCase):
    def test_sinh_khoa_va_parity(self):
        khoa = list(bytes.fromhex("133457799BBCDFF1"))
        cac_khoa = sinh_khoa_con(khoa)
        self.assertEqual(len(cac_khoa), 16)
        self.assertTrue(all(len(k) == 48 for k in cac_khoa))
        self.assertEqual(bit_sang_hex(cac_khoa[0]), "1B02EFFC7072")
        self.assertTrue(kiem_tra_parity_le(khoa))

    def test_ma_hoa_giai_ma(self):
        khoa = "133457799BBCDFF1"
        ban_ro = "0123456789ABCDEF"
        ban_ma = ma_hoa_khoi_des(ban_ro, khoa)
        self.assertEqual(ban_ma, "85E813540F0AB405")
        self.assertEqual(giai_ma_khoi_des(ban_ma, khoa), ban_ro)

    def test_thuan_nghich(self):
        khoa = "AABBCCDDEEFF0011"
        for ban_ro in ("0000000000000000", "FFFFFFFFFFFFFFFF",
                       "123456789ABCDEF0"):
            with self.subTest(ban_ro=ban_ro):
                ban_ma = ma_hoa_khoi_des(ban_ro, khoa)
                self.assertEqual(giai_ma_khoi_des(ban_ma, khoa), ban_ro)

    def test_in_trang_thai(self):
        ban_ma, log = ma_hoa_khoi_des_chi_tiet(
            "0123456789ABCDEF", "133457799BBCDFF1"
        )
        self.assertEqual(ban_ma, "85E813540F0AB405")
        self.assertIn("Vong 16", log)
        self.assertIn("Sau FP", log)


if __name__ == "__main__":
    unittest.main(verbosity=2)
