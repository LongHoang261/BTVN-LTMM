# tạo bảng AES-128
def nhan_gf(a, b):
    kq = 0
    for _ in range(8):
        if b & 1:
            kq ^= a
        bit_cao = a & 0x80
        a = (a << 1) & 0xFF
        if bit_cao:
            a ^= 0x1B
        b >>= 1
    return kq
def nghich_dao_gf(a):
    if a == 0:
        return 0
    kq, co_so, mu = 1, a, 254
    while mu:
        if mu & 1:
            kq = nhan_gf(kq, co_so)
        co_so = nhan_gf(co_so, co_so)
        mu >>= 1
    return kq
def xoay_bit_8bit(a, n):
    return ((a << n) | (a >> (8 - n))) & 0xFF
def tao_s_box():
    bang = []
    for i in range(256):
        x = nghich_dao_gf(i)
        y = (x ^ xoay_bit_8bit(x, 1) ^ xoay_bit_8bit(x, 2)
             ^ xoay_bit_8bit(x, 3) ^ xoay_bit_8bit(x, 4) ^ 0x63)
        bang.append(y)
    return bang
S_BOX = tao_s_box()
INV_S_BOX = [0] * 256
for i in range(256):
    INV_S_BOX[S_BOX[i]] = i
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1B, 0x36]
