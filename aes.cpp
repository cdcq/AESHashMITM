#include "aes.h"

#include "log.h"
#include <initializer_list>
#include <iomanip>
#include <string>
#include <sstream>

namespace AESLib {
    Status::Status() = default;

    Status::Status(const std::initializer_list<Byte> &bytes) {
        auto iter = bytes.begin();
        for (auto &i: value) {
            for (auto &j: i) {
                if (iter == bytes.end()) {
                    j = 0;
                } else {
                    j = *iter;
                    iter++;
                }
            }
        }
    }

    Status::Status(const std::initializer_list<Word> &words) {
        auto iter = words.begin();
        for (auto &i: value) {
            Word temp = 0;
            if (iter != words.end()) {
                temp = *iter;
                iter++;
            }
            for (int j = 0; j < 4; j++) {
                i[3 - j] = temp & 0xff;
                temp >>= 8;
            }
        }
    }

    bool Status::operator==(const Status &y) const {
        for (int i = 0; i < N_B; i++) {
            for (int j = 0; j < 4; j++) {
                if (value[i][j] != y.value[i][j]) {
                    return false;
                }
            }
        }
        return true;
    }

    void Status::operator+=(const Status &y) {
        for (int i = 0; i < N_B; i++) {
            for (int j = 0; j < 4; j++) {
                value[i][j] ^= y.value[i][j];
            }
        }
    }

    Status Status::operator+(const Status &y) {
        Status ret = {};
        for (int i = 0; i < N_B; i++) {
            for (int j = 0; j < 4; j++) {
                ret.value[i][j] = value[i][j] ^ y.value[i][j];
            }
        }
        return ret;
    }

    std::string Status::ToString() const {
        using namespace std;
        stringstream ss;
        for (auto &i: value) {
            for (auto j: i) {
                ss << setw(2) << setfill('0') << hex << (int) j << " ";
            }
            ss << endl;
        }
        return ss.str();
    }

    void Status::SubBytes() {
        for (auto &i: value) {
            for (auto &j: i) {
                j = S_BOX[j >> 4][j & 0xf];
            }
        }
    }

    void Status::InvSubBytes() {
        for (auto &i: value) {
            for (auto &j: i) {
                j = INV_S_BOX[j >> 4][j & 0xf];
            }
        }
    }

    void Status::ShiftRows() {
        using namespace std;
        Byte temp = value[1][0];
        value[1][0] = value[1][1];
        value[1][1] = value[1][2];
        value[1][2] = value[1][3];
        value[1][3] = temp;
        swap(value[2][0], value[2][2]);
        swap(value[2][1], value[2][3]);
        temp = value[3][3];
        value[3][3] = value[3][2];
        value[3][2] = value[3][1];
        value[3][1] = value[3][0];
        value[3][0] = temp;
    }

    void Status::InvShiftRows() {
        using namespace std;
        Byte temp = value[1][3];
        value[1][3] = value[1][2];
        value[1][2] = value[1][1];
        value[1][1] = value[1][0];
        value[1][0] = temp;
        swap(value[2][0], value[2][2]);
        swap(value[2][1], value[2][3]);
        temp = value[3][0];
        value[3][0] = value[3][1];
        value[3][1] = value[3][2];
        value[3][2] = value[3][3];
        value[3][3] = temp;
    }

    void Status::MixColumns() {
        static Byte matrix[4][4] = {
                0x2, 0x3, 0x1, 0x1,
                0x1, 0x2, 0x3, 0x1,
                0x1, 0x1, 0x2, 0x3,
                0x3, 0x1, 0x1, 0x2,
        };
        static Status temp = {};
        GFMatrixMul(matrix, value, temp.value);
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                value[i][j] = temp.value[i][j];
            }
        }
    }

    void Status::InvMixColumns() {
        static Byte matrix[4][4] = {
                0xe, 0xb, 0xd, 0x9,
                0x9, 0xe, 0xb, 0xd,
                0xd, 0x9, 0xe, 0xb,
                0xb, 0xd, 0x9, 0xe,
        };
        static Status temp = {};
        GFMatrixMul(matrix, value, temp.value);
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                value[i][j] = temp.value[i][j];
            }
        }
    }

    Byte GFMul(Byte x, Byte y) {
        // Multiplication in GF(2^8) for AESLib modulo x^8+x^4+x^3+x+1.
        Byte ret = 0;
        for (; x; x >>= 1) {
            if (x & 1)
                ret ^= y;
            if (y & 0x80) {
                y <<= 1;
                y ^= 0x1b;
            } else {
                y <<= 1;
            }
        }
        return ret;
    }

    void GFMatrixMul(Byte x[4][4], Byte y[4][4], Byte ret[4][4]) {
        for(int row = 0; row < 4; row++) {
            for(int col = 0; col < 4; col++) {
                ret[row][col] = 0;
                for(int i = 0; i < 4; i++) {
                    ret[row][col] ^= GFMul(x[row][i], y[i][col]);
                }
            }
        }
    }

    Byte GFInvSlow(Byte x) {
        for (int i = 0; i < 0xff; i++) {
            if (GFMul(i, x) == 1) {
                return i;
            }
        }
        return 0;
    }

    Byte ByteInWord(Word x, int y) {
        return x >> (24 - y * 8) & 0xff;
    }

    Word WordByByte(Byte x0, Byte x1, Byte x2, Byte x3) {
        return x0 << 24 | x1 << 16 | x2 << 8 | x3;
    }

    AES::AES() = default;

    AES::AES(const Byte *key, int n_k_, int n_r_) {
        n_k = n_k_;
        n_r = n_r_;

        KeyExpansion(key);
    }

    void AES::KeyExpansion(const Byte *key) {
        Word temp;
        for (int i = 0; i < n_k; i++) {
            w[i] = 0;
            for (int j = 0; j < 4; j++) {
                w[i] <<= 8;
                w[i] |= key[i * 4 + j];
            }
        }
        Byte r_con = 1;
        for (int i = n_k; i < N_B * (n_r + 1); i++) {
            temp = w[i - 1];
            if (i % n_k == 0) {
                temp = SubWord(RotWord(temp)) ^ (r_con << 24);
                r_con = GFMul(2, r_con);
            } else if (n_k > 6 and i % n_k == 4) {
                temp = SubWord(temp);
            }
            w[i] = w[i - n_k] ^ temp;
        }
    }

    void AES::AddRoundKey(Status &status, int round) const {
        int base = round * 4;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                status.value[i][j] ^= (w[base + j] >> (24 - i * 8)) & 0xff;
            }
        }
    }

    void AES::Round(Status &status, int round) const {
        status.SubBytes();
        status.ShiftRows();
        if (round != n_r)
            status.MixColumns();
        AddRoundKey(status, round);
    }

    void AES::InvRound(Status &status, int round) const {
        AddRoundKey(status, round);
        if (round != n_r)
            status.InvMixColumns();
        status.InvShiftRows();
        status.InvSubBytes();
    }

    Status AES::Cipher(Status status) const {
        AddRoundKey(status, 0);
        for (int round = 1; round < n_r; round++) {
            Round(status, round);
        }
        status.SubBytes();
        status.ShiftRows();
        // No MixColumns in last round.
        AddRoundKey(status, n_r);
        return status;
    }

    Status AES::InvCipher(Status status) const {
        AddRoundKey(status, n_r);
        for (int round = n_r - 1; round >= 1; round--) {
            status.InvShiftRows();
            status.InvSubBytes();
            AddRoundKey(status, round);
            status.InvMixColumns();
        }
        status.InvShiftRows();
        status.InvSubBytes();
        AddRoundKey(status, 0);
        return status;
    }

    Status AES::CompressionFunction(Status status) const {
        return Cipher(status) + status;
    }

    void AES::ReadW(Word *w_) const {
        for (int i = 0; i < N_B * (n_r + 1); i++) {
            w_[i] = w[i];
        }
    }

    inline Byte SBox(Byte x) {
        return S_BOX[x >> 4][x & 0xf];
    }

    Word SubWord(Word x) {
        Word ret = 0;
        for (int i = 0; i < 4; i++, x >>= 8) {
            ret |= SBox(x & 0xff) << (i * 8);
        }
        return ret;
    }

    Word InvSubWord(Word x) {
        Word ret = 0;
        for (int i = 0; i < 4; i++, x >>= 8) {
            ret |= SBox(x & 0xff) << (i * 8);
        }
        return ret;
    }

    inline Word RotWord(Word x) {
        return x << 8 | x >> 24;
    }

    Word InvRotWord(Word x) {
        return x >> 8 | (x & 0xff) << 24;
    }

    void AESTest() {
        using namespace AESLib;
        using namespace std;

        // Data from FIPS 197 appendix B round 1st.
        Status start_of_round(initializer_list<Byte>(
                {
                        0x19, 0xa0, 0x9a, 0xe9,
                        0x3d, 0xf4, 0xc6, 0xf8,
                        0xe3, 0xe2, 0x8d, 0x48,
                        0xbe, 0x2b, 0x2a, 0x08,
                }
        ));
        Status after_sub_bytes(initializer_list<Byte>(
                {
                        0xd4, 0xe0, 0xb8, 0x1e,
                        0x27, 0xbf, 0xb4, 0x41,
                        0x11, 0x98, 0x5d, 0x52,
                        0xae, 0xf1, 0xe5, 0x30,
                }
        ));
        Status after_shift_rows(initializer_list<Byte>(
                {
                        0xd4, 0xe0, 0xb8, 0x1e,
                        0xbf, 0xb4, 0x41, 0x27,
                        0x5d, 0x52, 0x11, 0x98,
                        0x30, 0xae, 0xf1, 0xe5,
                }
        ));
        Status after_mix_columns(initializer_list<Byte>(
                {
                        0x04, 0xe0, 0x48, 0x28,
                        0x66, 0xcb, 0xf8, 0x06,
                        0x81, 0x19, 0xd3, 0x26,
                        0xe5, 0x9a, 0x7a, 0x4c,
                }
        ));
        Status result_of_round(initializer_list<Byte>(
                {
                        0xa4, 0x68, 0x6b, 0x02,
                        0x9c, 0x9f, 0x5b, 0x6a,
                        0x7f, 0x35, 0xea, 0x50,
                        0xf2, 0x2b, 0x43, 0x49,
                }
        ));
        Byte key[16] = {
                0x2b, 0x7e, 0x15, 0x16,
                0x28, 0xae, 0xd2, 0xa6,
                0xab, 0xf7, 0x15, 0x88,
                0x09, 0xcf, 0x4f, 0x3c,
        };

        AES aes(key);
        Word w[60] = {};
        aes.ReadW(w);
        if (
                w[40] == (Word) 0xd014f9a8 &&
                w[41] == (Word) 0xc9ee2589 &&
                w[42] == (Word) 0xe13f0cc8 &&
                w[43] == (Word) 0xb6630ca6
                ) {
            Log::Correct("KeyExpansion test: passed");
        } else {
            Log::Error("KeyExpansion test: failed");
        }

        Status x = start_of_round;
        x.SubBytes();
        if (x == after_sub_bytes) {
            Log::Correct("SubBytes test: passed");
        } else {
            Log::Error("SubBytes test: failed");
        }
        x = after_sub_bytes;
        x.InvSubBytes();
        if (x == start_of_round) {
            Log::Correct("InvSubBytes test: passed");
        } else {
            Log::Error("InvSubBytes test: failed");
        }
        x = after_sub_bytes;
        x.ShiftRows();
        if (x == after_shift_rows) {
            Log::Correct("ShiftRows test: passed");
        } else {
            Log::Error("ShiftRows test: failed");
        }
        x = after_shift_rows;
        x.InvShiftRows();
        if (x == after_sub_bytes) {
            Log::Correct("InvShiftRows test: passed");
        } else {
            Log::Error("InvShiftRows test: failed");
        }
        x = after_shift_rows;
        x.MixColumns();
        if (x == after_mix_columns) {
            Log::Correct("MixColumns test: passed");
        } else {
            Log::Error("MixColumns test: failed");
        }
        x = after_mix_columns;
        x.InvMixColumns();
        if (x == after_shift_rows) {
            Log::Correct("InvMixColumns test: passed");
        } else {
            Log::Error("InvMixColumns test: failed");
        }
        x = after_mix_columns;
        aes.AddRoundKey(x, 1);
        if (x == result_of_round) {
            Log::Correct("AddRoundKey test: passed\n"
                         "\tThis result is rely on the result of KeyExpansion test.");
        } else {
            Log::Error("AddRoundKey test: failed\n"
                       "\tThis result is rely on the result of KeyExpansion test.");
        }

        Status input(initializer_list<Byte>(
                {
                        0x32, 0x88, 0x31, 0xe0,
                        0x43, 0x5a, 0x31, 0x37,
                        0xf6, 0x30, 0x98, 0x07,
                        0xa8, 0x8d, 0xa2, 0x34,
                }
        ));
        Status output(initializer_list<Byte>(
                {
                        0x39, 0x02, 0xdc, 0x19,
                        0x25, 0xdc, 0x11, 0x6a,
                        0x84, 0x09, 0x85, 0x0b,
                        0x1d, 0xfb, 0x97, 0x32,
                }
        ));
        Status res = aes.Cipher(input);
        if (res == output) {
            Log::Correct("Full round test: passed");
        } else {
            Log::Error("Full round test: failed");
        }
        res = aes.InvCipher(output);
        if (res == input) {
            Log::Correct("Full round inverse test: passed");
        } else {
            Log::Error("Full round test: failed");
        }
    }

} // AESLib
