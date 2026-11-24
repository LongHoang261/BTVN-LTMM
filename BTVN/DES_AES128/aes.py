from aes_tables import S_BOX, INV_S_BOX, RCON, nhan_gf
KICH_THUOC_KHOI = 16
def _doc_hex(chuoi, ten):
    if not isinstance(chuoi, str):
        raise TypeError(f"{ten} Lỗi(hex)")
    try:
        du_lieu = bytes.fromhex(chuoi)
    except ValueError:
        raise ValueError(f"{ten} lỗi(hex)")
    if len(du_lieu) != KICH_THUOC_KHOI:
        raise ValueError(f"{ten} (16 byte)")
    return list(du_lieu)
def bytes_to_state(ds_byte):
    if len(ds_byte) != 16:
        raise ValueError("AES có 16 byte")
    state = [[0] * 4 for _ in range(4)]
    for cot in range(4):
        for hang in range(4):
            state[hang][cot] = ds_byte[cot * 4 + hang]
    return state
def state_to_bytes(state):
    if len(state) != 4 or any(len(hang) != 4 for hang in state):
        raise ValueError("State: ma trận 4x4")
    ds_byte = []
    for cot in range(4):
        for hang in range(4):
            ds_byte.append(state[hang][cot])
    return ds_byte
def _state_to_hex(state):
    return bytes(state_to_bytes(state)).hex().upper()
def thay_byte(state):
    for hang in range(4):
        for cot in range(4):
            state[hang][cot] = S_BOX[state[hang][cot]]
def thay_byte_nguoc(state):
    for hang in range(4):
        for cot in range(4):
            state[hang][cot] = INV_S_BOX[state[hang][cot]]
def dich_hang(state):
    for hang in range(1, 4):
        state[hang] = state[hang][hang:] + state[hang][:hang]


def dich_hang_nguoc(state):
    for hang in range(1, 4):
        state[hang] = state[hang][-hang:] + state[hang][:-hang]


def tron_cot(state):
    for cot in range(4):
        a0, a1, a2, a3 = (state[hang][cot] for hang in range(4))
        state[0][cot] = nhan_gf(a0, 2) ^ nhan_gf(a1, 3) ^ a2 ^ a3
        state[1][cot] = a0 ^ nhan_gf(a1, 2) ^ nhan_gf(a2, 3) ^ a3
        state[2][cot] = a0 ^ a1 ^ nhan_gf(a2, 2) ^ nhan_gf(a3, 3)
        state[3][cot] = nhan_gf(a0, 3) ^ a1 ^ a2 ^ nhan_gf(a3, 2)


def tron_cot_nguoc(state):
    for cot in range(4):
        a0, a1, a2, a3 = (state[hang][cot] for hang in range(4))
        state[0][cot] = (nhan_gf(a0, 0x0E) ^ nhan_gf(a1, 0x0B)
                         ^ nhan_gf(a2, 0x0D) ^ nhan_gf(a3, 0x09))
        state[1][cot] = (nhan_gf(a0, 0x09) ^ nhan_gf(a1, 0x0E)
                         ^ nhan_gf(a2, 0x0B) ^ nhan_gf(a3, 0x0D))
        state[2][cot] = (nhan_gf(a0, 0x0D) ^ nhan_gf(a1, 0x09)
                         ^ nhan_gf(a2, 0x0E) ^ nhan_gf(a3, 0x0B))
        state[3][cot] = (nhan_gf(a0, 0x0B) ^ nhan_gf(a1, 0x0D)
                         ^ nhan_gf(a2, 0x09) ^ nhan_gf(a3, 0x0E))


def cong_khoa_vong(state, khoa_vong):
    for hang in range(4):
        for cot in range(4):
            state[hang][cot] ^= khoa_vong[hang][cot]


def _xoay_word(w):
    return w[1:] + w[:1]


def _thay_word(w):
    return [S_BOX[x] for x in w]


def mo_rong_khoa(khoa_byte):
    if len(khoa_byte) != 16:
        raise ValueError("AES-128 có 16 byte")
    w = [list(khoa_byte[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        tam = w[i - 1].copy()
        if i % 4 == 0:
            tam = _thay_word(_xoay_word(tam))
            tam[0] ^= RCON[i // 4]
        w.append([w[i - 4][j] ^ tam[j] for j in range(4)])
    ds_khoa_vong = []
    for vong in range(11):
        khoa_vong = [[0] * 4 for _ in range(4)]
        for cot in range(4):
            for hang in range(4):
                khoa_vong[hang][cot] = w[vong * 4 + cot][hang]
        ds_khoa_vong.append(khoa_vong)
    return ds_khoa_vong
def _ma_hoa_aes(aes_ro, aes_khoa):
    ban_ro = _doc_hex(aes_ro, "Ban ro")
    khoa = _doc_hex(aes_khoa, "Khoa")
    ds_khoa_vong = mo_rong_khoa(khoa)
    state = bytes_to_state(ban_ro)
    log = []

    cong_khoa_vong(state, ds_khoa_vong[0])
    log.append(f"Vong 00 | AddRoundKey K0={_state_to_hex(ds_khoa_vong[0])} | State={_state_to_hex(state)}")

    for vong in range(1, 10):
        thay_the_byte(state)
        sub_hex = _state_to_hex(state)
        dich_hang(state)
        shift_hex = _state_to_hex(state)
        tron_cot(state)
        mix_hex = _state_to_hex(state)
        cong_khoa_vong(state, ds_khoa_vong[vong])
        log.append(f"Vong {vong:02d} | SubBytes={sub_hex} | ShiftRows={shift_hex}")
        log.append(f"         MixColumns={mix_hex} | AddRoundKey={_state_to_hex(state)}")

    thay_the_byte(state)
    sub_hex = _state_to_hex(state)
    dich_hang(state)
    shift_hex = _state_to_hex(state)
    cong_khoa_vong(state, ds_khoa_vong[10])
    ban_ma = _state_to_hex(state)
    log.append(f"Vong 10 | SubBytes={sub_hex} | ShiftRows={shift_hex}")
    log.append(f"         AddRoundKey K10={_state_to_hex(ds_khoa_vong[10])}")
    log.append(f"Ban ma cuoi: {ban_ma}")
    return ban_ma, log


def ma_hoa_aes_128(aes_ro, aes_khoa):
    return _ma_hoa_aes(aes_ro, aes_khoa)[0]


def ma_hoa_aes_128_chi_tiet(aes_ro, aes_khoa):
    ban_ma, log = _ma_hoa_aes(aes_ro, aes_khoa)
    return ban_ma, "\n".join(log)


def giai_ma_aes_128(aes_ban_ma, aes_khoa):
    ban_ma = _doc_hex(aes_ban_ma, "Ban ma")
    khoa = _doc_hex(aes_khoa, "Khoa")
    ds_khoa_vong = mo_rong_khoa(khoa)
    state = bytes_to_state(ban_ma)

    cong_khoa_vong(state, ds_khoa_vong[10])
    for vong in range(9, 0, -1):
        dich_hang_nguoc(state)
        thay_the_byte_nguoc(state)
        cong_khoa_vong(state, ds_khoa_vong[vong])
        tron_cot_nguoc(state)

    dich_hang_nguoc(state)
    thay_the_byte_nguoc(state)
    cong_khoa_vong(state, ds_khoa_vong[0])
    return bytes(state_to_bytes(state)).hex().upper()
