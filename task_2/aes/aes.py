from aes._matrices import *


def _x_time(a):
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def _block_to_matrix(block):
    matrix = []
    for i in range(16):
        byte = (block >> (8 * (15 - i))) & 0xFF
        if i % 4 == 0:
            matrix.append([byte])
        else:
            matrix[int(i / 4)].append(byte)
    return matrix


def _matrix_to_block(matrix):
    block = 0
    for i in range(4):
        for j in range(4):
            block |= (matrix[i][j] << (120 - 8 * (4 * i + j)))
    return block


def _mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ _x_time(a[0] ^ a[1])
    a[1] ^= t ^ _x_time(a[1] ^ a[2])
    a[2] ^= t ^ _x_time(a[2] ^ a[3])
    a[3] ^= t ^ _x_time(a[3] ^ u)


def _inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]


def _mix_columns(s):
    for i in range(4):
        _mix_single_column(s[i])


def _inv_mix_columns(s):
    for i in range(4):
        u = _x_time(_x_time(s[i][0] ^ s[i][2]))
        v = _x_time(_x_time(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    _mix_columns(s)


def _inv_sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]


def _shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def _sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]


def _add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


def _round_decrypt(state_matrix, key_matrix):
    _add_round_key(state_matrix, key_matrix)
    _inv_mix_columns(state_matrix)
    _inv_shift_rows(state_matrix)
    _inv_sub_bytes(state_matrix)


def _round_encrypt(state_matrix, key_matrix):
    _sub_bytes(state_matrix)
    _shift_rows(state_matrix)
    _mix_columns(state_matrix)
    _add_round_key(state_matrix, key_matrix)


def _round_key_gen(cipher_key):
    round_key = _block_to_matrix(cipher_key)
    for i in range(4, 4 * 11):
        round_key.append([])
        if i % 4 == 0:
            byte = round_key[i - 4][0] ^ s_box[round_key[i - 1][1]] ^ rcon[i // 4]
            round_key[i].append(byte)

            for j in range(1, 4):
                byte = round_key[i - 4][j] ^ s_box[round_key[i - 1][(j + 1) % 4]]
                round_key[i].append(byte)
        else:
            for j in range(4):
                byte = round_key[i - 4][j] ^ round_key[i - 1][j]
                round_key[i].append(byte)
    return round_key


def encrypt(block, cipher_key):
    round_key = _round_key_gen(cipher_key)
    block_matrix = _block_to_matrix(block)

    _add_round_key(block_matrix, round_key[:4])
    for i in range(1, 10):
        _round_encrypt(block_matrix, round_key[4 * i: 4 * (i + 1)])

    _sub_bytes(block_matrix)
    _shift_rows(block_matrix)
    _add_round_key(block_matrix, round_key[40:])

    return _matrix_to_block(block_matrix)


def decrypt(cipher, cipher_key):
    round_key = _round_key_gen(cipher_key)
    cipher_matrix = _block_to_matrix(cipher)

    _add_round_key(cipher_matrix, round_key[40:])
    _inv_shift_rows(cipher_matrix)
    _inv_sub_bytes(cipher_matrix)

    for i in range(9, 0, -1):
        _round_decrypt(cipher_matrix, round_key[4 * i: 4 * (i + 1)])
    _add_round_key(cipher_matrix, round_key[:4])

    return _matrix_to_block(cipher_matrix)
