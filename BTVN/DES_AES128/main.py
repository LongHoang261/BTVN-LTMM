from aes import ma_hoa_aes_128_chi_tiet, giai_ma_aes_128
from des import ma_hoa_khoi_des_chi_tiet, giai_ma_khoi_des


def main():
    print("MA HOA AES-128")
    aes_ro = "00112233445566778899AABBCCDDEEFF"
    aes_khoa = "000102030405060708090A0B0C0D0E0F"
    aes_ban_ma, aes_log = ma_hoa_aes_128_chi_tiet(aes_ro, aes_khoa)
    print("Ban ro :", aes_ro)
    print("Khoa   :", aes_khoa)
    print(aes_log)
    print("Giải mã:", giai_ma_aes_128(aes_ban_ma, aes_khoa))

    print("\nMA HOA DES")
    des_ro = "0123456789ABCDEF"
    des_khoa = "133457799BBCDFF1"
    des_ban_ma, des_log = ma_hoa_khoi_des_chi_tiet(des_ro, des_khoa)
    print("Ban ro :", des_ro)
    print("Khoa   :", des_khoa)
    print(des_log)
    print("Giải mã:", giai_ma_khoi_des(des_ban_ma, des_khoa))


if __name__ == "__main__":
    main()
