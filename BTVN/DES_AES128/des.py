from des_tables import IP, FP, E, P, PC1, PC2, SO_BUOC_DICH, S_BOXES


KICH_THUOC_KHOI = 8


def _doc_hex(chuoi, ten):
    if not isinstance(chuoi, str):
        raise TypeError(f"{ten} (Hex)")
    try:
        du_lieu = bytes.fromhex(chuoi)
    except ValueError:
        raise ValueError(f"{ten} Lỗi(hex)")
    if len(du_lieu) != KICH_THUOC_KHOI:
        raise ValueError(f"{ten} (8 byte)")
    return list(du_lieu)


def bytes_sang_bit(ds_byte):
    return [(byte >> i) & 1 for byte in ds_byte for i in range(7, -1, -1)]


def bit_sang_hex(ds_bit):
    if not ds_bit or len(ds_bit) % 4 != 0 or any(bit not in (0, 1) for bit in ds_bit):
        raise ValueError("Lỗi")
    kq = 0
    for bit in ds_bit:
        kq = (kq << 1) | bit
    return f"{kq:0{len(ds_bit) // 4}X}"


def hoan_vi(ds_bit, bang):
    if any(vi_tri < 1 or vi_tri > len(ds_bit) for vi_tri in bang):
        raise ValueError("Lỗi")
    return [ds_bit[vi_tri - 1] for vi_tri in bang]


def sinh_khoa_con(khoa_byte):
    if len(khoa_byte) != 8:
        raise ValueError("Lỗi (cần 8 byte)")
    khoa_bit = bytes_sang_bit(khoa_byte)
    khoa_56 = hoan_vi(khoa_bit, PC1)
    C, D = khoa_56[:28], khoa_56[28:]
    ds_khoa = []
    for buoc in SO_BUOC_DICH:
        C = C[buoc:] + C[:buoc]
        D = D[buoc:] + D[:buoc]
        ds_khoa.append(hoan_vi(C + D, PC2))
    return ds_khoa


def kiem_tra_parity_le(khoa_byte):
    if len(khoa_byte) != 8:
        raise ValueError("Lỗi(cần 8 byte)")
    return all(byte.bit_count() % 2 == 1 for byte in khoa_byte)


def ham_feistel(nua_phai, khoa_con):
    if len(nua_phai) != 32 or len(khoa_con) != 48:
        raise ValueError("Feistel (R 32 bit, khóa con 48 bit))")
    mo_rong = hoan_vi(nua_phai, E)
    xor_khoa = [a ^ b for a, b in zip(mo_rong, khoa_con)]
    dau_ra_sbox = []

    for i in range(8):
        khoi = xor_khoa[i * 6:(i + 1) * 6]
        hang = (khoi[0] << 1) | khoi[5]
        cot = (khoi[1] << 3) | (khoi[2] << 2) | (khoi[3] << 1) | khoi[4]
        gia_tri = S_BOXES[i][hang][cot]
        dau_ra_sbox.extend((gia_tri >> bit) & 1 for bit in (3, 2, 1, 0))
    return hoan_vi(dau_ra_sbox, P)


def _ma_hoa_des(des_ro, des_khoa):
    ban_ro = _doc_hex(des_ro, "Ban ro")
    khoa = _doc_hex(des_khoa, "Khoa")
    ds_khoa = sinh_khoa_con(khoa)
    sau_ip = hoan_vi(bytes_sang_bit(ban_ro), IP)
    L, R = sau_ip[:32], sau_ip[32:]
    log = [f"Sau IP | L0={bit_sang_hex(L)} | R0={bit_sang_hex(R)}"]

    for vong in range(16):
        L_moi = R
        f_ra = ham_feistel(R, ds_khoa[vong])
        R_moi = [L[i] ^ f_ra[i] for i in range(32)]
        L, R = L_moi, R_moi
        log.append(f"Vong {vong + 1:02d} | K={bit_sang_hex(ds_khoa[vong])} | L={bit_sang_hex(L)} | R={bit_sang_hex(R)}")

    ban_ma_bit = hoan_vi(R + L, FP)
    ban_ma = bit_sang_hex(ban_ma_bit)
    log.append(f"Sau FP | Ban ma={ban_ma}")
    return ban_ma, log


def ma_hoa_khoi_des(des_ro, des_khoa):
    return _ma_hoa_des(des_ro, des_khoa)[0]


def ma_hoa_khoi_des_chi_tiet(des_ro, des_khoa):
    ban_ma, log = _ma_hoa_des(des_ro, des_khoa)
    return ban_ma, "\n".join(log)


def giai_ma_khoi_des(des_ban_ma, des_khoa):
    ban_ma = _doc_hex(des_ban_ma, "Ban ma")
    khoa = _doc_hex(des_khoa, "Khoa")
    ds_khoa = sinh_khoa_con(khoa)[::-1]
    sau_ip = hoan_vi(bytes_sang_bit(ban_ma), IP)
    L, R = sau_ip[:32], sau_ip[32:]

    for khoa_con in ds_khoa:
        L_moi = R
        f_ra = ham_feistel(R, khoa_con)
        R_moi = [L[i] ^ f_ra[i] for i in range(32)]
        L, R = L_moi, R_moi

    ban_ro_bit = hoan_vi(R + L, FP)
    return bit_sang_hex(ban_ro_bit)
