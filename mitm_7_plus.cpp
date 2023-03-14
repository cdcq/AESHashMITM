#include "mitm_7_plus.h"

#include "aes.h"
#include "log.h"
#include <random>
#include <set>
#include <string>
#include <sstream>

namespace MITM7Plus {
    bool ChunkResult::operator<(MITM7Plus::ChunkResult y) const {
        return match < y.match;
    }

    Structure::Structure(AESLib::Status h_n_) {
        h_n = h_n_;

        Init();
    }

    Structure::Structure(
            AESLib::Status h_n_,
            AESLib::Word const_key_0,
            AESLib::Word const_key_1,
            AESLib::Word const_key_2,
            AESLib::Word const_0_,
            AESLib::Word const_1_,
            AESLib::Word const_2_0,
            AESLib::Word const_2_1,
            AESLib::Word const_2_2,
            AESLib::Word const_2_3
    ) {
        h_n = h_n_;
        const_key[0] = const_key_0;
        const_key[1] = const_key_1;
        const_key[2] = const_key_2;
        const_0 = const_0_;
        const_1 = const_1_;
        const_2[0] = const_2_0;
        const_2[1] = const_2_1;
        const_2[2] = const_2_2;
        const_2[3] = const_2_3;
    }

    void Structure::Init() {
        std::random_device rd;
        std::mt19937 mt(rd());

        for (auto &i: const_key) {
            i = mt();
        }
        const_0 = mt() & 0x0000ffff;
        const_1 = mt() & 0x00ffffff;
        for (auto &i: const_2) {
            i = mt() & 0x0000ffff;
        }
    }

    AESLib::Word Structure::CalculateNeutralKey(AESLib::Byte neutral_1, AESLib::Byte neutral_2) const {
        // Neutral 1 is #key3[7]. Neutral 2 is #12[5].
        // The result is #key3[4, 5, 6, 7].
        using namespace AESLib;
        static Byte solution[3][5] = {
                0xf7, 0x00, 0xf4, 0xf6, 0xf4,
                0xf6, 0x01, 0xf4, 0xf5, 0xf6,
                0xf6, 0x00, 0xf7, 0xf4, 0xf4,
        };

        Byte elements[5] = {
                neutral_1, neutral_2,
                ByteInWord(const_1, 1),
                ByteInWord(const_1, 2),
                ByteInWord(const_1, 3),
        };
        Word neutral_key = 0;
        for (auto &i: solution) {
            Byte temp = 0;
            for (int j = 0; j < 5; j++) {
                temp ^= GFMul(i[j], elements[j]);
            }
            neutral_key <<= 8;
            neutral_key |= temp;
        }
        neutral_key <<= 8;
        neutral_key |= neutral_1;
        return neutral_key;
    }

    AESLib::AES Structure::InvKeyGen(AESLib::Word neutral_key) const {
        using namespace AESLib;
        Word w[32] = {};
        w[3 << 2 | 0] = neutral_key ^ const_key[0];
        w[3 << 2 | 1] = neutral_key;
        w[3 << 2 | 2] = const_key[1];
        w[3 << 2 | 3] = const_key[2];
        for (int i = 11; i >= 0; i--) {
            Word temp = w[i + 3];
            if (not(i & 0x3)) {
                temp = SubWord(RotWord(temp)) ^ ((1 << (i >> 2)) << 24);
                // R con can be 4 2 1 when 'i' is 8 4 0.
            }
            w[i] = w[i + 4] ^ temp;
        }
        Byte key[16] = {};
        for (int i = 0; i < 4; i++) {
            for (int j = 3; j >= 0; j--) {
                key[i << 2 | j] = w[i] & 0xff;
                w[i] >>= 8;
            }
        }
        AES aes(key, 4, 7);
        return aes;
    }

    AESLib::Status Structure::CalculateForwardStart(AESLib::Word neutral) const {
        using namespace AESLib;
        static Byte factor[4][2][3] = {
                0xd1, 0xb9, 0xd1,
                0x69, 0xd1, 0x68,
                0xd1, 0xd1, 0xb9,
                0x69, 0x68, 0xd1,
                0xd1, 0xd1, 0xb9,
                0x69, 0x68, 0xd1,
                0xd1, 0xb9, 0xd1,
                0x69, 0xd1, 0x68,
        };
        Status ret = {};
        for (int col = 0; col < 4; col++) {
            for (int i = 0; i < 2; i++) {
                ret.value[(i - col + 5) & 3][col] =
                        GFMul(factor[col][i][0], ByteInWord(neutral, col)) ^
                        GFMul(factor[col][i][1], const_2[col] >> 8 & 0xff) ^
                        GFMul(factor[col][i][2], const_2[col] & 0xff);
            }
            ret.value[3 - col][col] = ByteInWord(neutral, col);
        }
        return ret;
    }

    InitialStructure Structure::CreateInitialStructure(
            AESLib::Word forward_neutral,
            AESLib::Word backward_neutral
    ) const {
        using namespace AESLib;

        Status status = {};
        status.value[0][0] = ByteInWord(forward_neutral, 1);
        status.value[1][1] = ByteInWord(forward_neutral, 2);
        status.value[2][2] = const_0 >> 8 & 0xff;
        status.value[3][3] = const_0 & 0xff;
        AES aes = InvKeyGen(CalculateNeutralKey(
                ByteInWord(forward_neutral, 3),
                ByteInWord(forward_neutral, 2)
        ));

        // We shouldn't add k3 to status, cause the #13 is the true backward start
        // since #12 = #13.
        // aes.AddRoundKey(status, 3);

        aes.Round(status, 4);
        status.SubBytes();
        status.ShiftRows();

        Status forward_start = CalculateForwardStart(backward_neutral);
        for (int col = 0; col < 4; col++) {
            for (int i = 0; i < 3; i++) {
                int row = (i - col + 5) & 3;
                status.value[row][col] = forward_start.value[row][col];
            }
        }

        return {
                aes,
                status,
        };
    }

    AESLib::Word Structure::ForwardComputation(AESLib::Word neutral) const {
        using namespace AESLib;

        InitialStructure initial_structure = CreateInitialStructure(
                neutral,
                0
        );

        Status status = initial_structure.forward_start;
        AES *aes = &initial_structure.aes;

        status.MixColumns();
        aes->AddRoundKey(status, 5);
        aes->Round(status, 6);
        aes->Round(status, 7);
        status += h_n;
        aes->AddRoundKey(status, 0);
        aes->Round(status, 1);
        status.SubBytes();
        status.ShiftRows();

        // Don't forget the k2.
        Status k_2 = {};
        Word w[60] = {};
        aes->ReadW(w);
        for (int col = 0; col < 4; col++) {
            for (int i = 0; i < 4; i++) {
                k_2.value[i][col] = ByteInWord(w[8 | col], i);
            }
        }
        k_2.InvMixColumns();
        status += k_2;

        return ForwardMatch(status);
    }

    AESLib::Byte Structure::ForwardMatch(const AESLib::Status &status, int col) {
        using namespace AESLib;
        static const int row1[4] = {0, 1, 0, 1};
        static const int row2[4] = {2, 3, 2, 3};
        static const Byte factor1[4] = {0xd, 0xd, 0xe, 0xe};
        static const Byte factor2[4] = {0xe, 0xe, 0xd, 0xd};
        return GFMul(factor1[col], status.value[row1[col]][col])
               ^ GFMul(factor2[col], status.value[row2[col]][col]);
    }

    AESLib::Word Structure::ForwardMatch(const AESLib::Status &status) {
        return AESLib::WordByByte(
                ForwardMatch(status, 0),
                0,
                ForwardMatch(status, 2),
                ForwardMatch(status, 3)
        );
    }

    AESLib::Word Structure::BackwardComputation(AESLib::Word neutral) const {
        using namespace AESLib;

        InitialStructure initial_structure = CreateInitialStructure(
                0,
                neutral
        );

        Status status = initial_structure.forward_start;
        AES *aes = &initial_structure.aes;

        status.InvShiftRows();
        status.InvSubBytes();
        aes->InvRound(status, 4);
        aes->InvRound(status, 3);

        // k2 should be added at forward chunk.
        // aes->AddRoundKey(status, 2);

        return BackwardMatch(status);
    }

    AESLib::Byte Structure::BackwardMatch(const AESLib::Status &status, int col) {
        using namespace AESLib;
        static const Byte matrix[4][4] = {
                0xe, 0xb, 0xd, 0x9,
                0x9, 0xe, 0xb, 0xd,
                0xd, 0x9, 0xe, 0xb,
                0xb, 0xd, 0x9, 0xe,
        };
        static const int row1[4] = {0, 1, 0, 1};
        static const int row2[4] = {2, 3, 2, 3};
        static const Byte factor1[4] = {0xd, 0xd, 0xe, 0xe};
        static const Byte factor2[4] = {0xe, 0xe, 0xd, 0xd};
        Byte c_0 = GFMul(matrix[row1[col]][col], status.value[col][col]);
        Byte c_1 = GFMul(matrix[row2[col]][col], status.value[col][col]);
        for (int i = 0; i < 4; i++) {
            c_0 ^= GFMul(matrix[row1[col]][i], status.value[i][col]);
            c_1 ^= GFMul(matrix[row2[col]][i], status.value[i][col]);
        }
        return GFMul(factor1[col], c_0) ^ GFMul(factor2[col], c_1);
    }

    AESLib::Word Structure::BackwardMatch(const AESLib::Status &status) {
        return AESLib::WordByByte(
                BackwardMatch(status, 0),
                0,
                BackwardMatch(status, 2),
                BackwardMatch(status, 3)
        );
    }

    bool Structure::CheckNeutral(
            AESLib::Word forward_neutral, AESLib::Word backward_neutral
    ) const {
        using namespace AESLib;

        InitialStructure initial_structure = CreateInitialStructure(
                forward_neutral,
                backward_neutral
        );
        Status status = initial_structure.forward_start;
        AES *aes = &initial_structure.aes;

        status.MixColumns();
        aes->AddRoundKey(status, 5);
        aes->Round(status, 6);
        aes->Round(status, 7);
        status += h_n;
        return aes->CompressionFunction(status) == h_n;
    }

    Result Structure::Compute() {
        using namespace AESLib;
        using namespace std;

        multiset<ChunkResult> forward_results = {};
        for (int i = 0; i < 0xffffff; i++) {
            forward_results.insert(ChunkResult(
                    {
                            (Word) i,
                            ForwardComputation(i)
                    }
            ));
        }

        for (int i = 0; i < 0xffff; i++) {
            for (int j = 0; j < 0xffff; j++) {
                Word neutral = (Word) i << 16 | j;
                ChunkResult backward_result = {
                        neutral,
                        BackwardComputation(neutral)
                };
                auto iter = forward_results.lower_bound(backward_result);
                for (; iter != forward_results.end() &&
                       iter->match == backward_result.match; iter++) {
                    if (CheckNeutral(iter->neutral, backward_result.neutral)) {
                        return {
                                iter->neutral,
                                backward_result.neutral
                        };
                    }
                }
            }
        }
        return {};
    }

    void Structure::Test(
            const AESLib::AES &aes,
            AESLib::Word forward_neutral,
            AESLib::Word backward_neutral
    ) {
        using namespace AESLib;

        bool neutral_key_flag = true;
        for (int i = 0x3e; i < 0xff; i++) {
            for (int j = 0x0b; j < 0xff; j++) {
                Word neutral_key = CalculateNeutralKey(i, j);
                Status temp = {};
                temp.value[1][1] = j;
                for (int k = 0; k < 4; k++) {
                    temp.value[k][1] ^= ByteInWord(neutral_key, k);
                }
                temp.InvMixColumns();
                for (int k = 1; k < 4; k++) {
                    if (temp.value[k][1] != ByteInWord(const_1, k)) {
                        neutral_key_flag = false;
                    }
                }
            }
        }
        if (neutral_key_flag) {
            Log::Correct("Calculate neutral key test: passed");
        } else {
            Log::Error("Calculate neutral key test: failed");
        }

        Word w[32] = {};
        aes.ReadW(w);
        AES inv_aes = InvKeyGen(w[13]);
        Word inv_w[32] = {};
        inv_aes.ReadW(inv_w);
        bool inv_key_gen_flag = true;
        for (int i = 0; i < 32; i++) {
            if (w[i] != inv_w[i]) {
                inv_key_gen_flag = false;
                break;
            }
        }
        if (inv_key_gen_flag) {
            Log::Correct("Inv key gen test: passed");
        } else {
            Log::Error("Inv key gen test: failed");
        }

        Status temp_status = {};
        bool forward_start_flag = true;
        for (int i = 0; i < 0xff; i++) {
            Word neutral = (Word) i << 24;
            for (int j = 0; j < 4; j++) {
                temp_status = CalculateForwardStart(neutral);
                temp_status.MixColumns();
                if (temp_status.value[j & 1][j] != ByteInWord(const_2[j], 2) ||
                    temp_status.value[j & 1 | 2][j] != ByteInWord(const_2[j], 3)) {
                    forward_start_flag = false;
                }
                neutral >>= 8;
            }
        }
        if (forward_start_flag) {
            Log::Correct("Forward start test: passed");
        } else {
            Log::Error("Forward start test: failed");
        }

        if (ForwardComputation(forward_neutral) == BackwardComputation(backward_neutral)
            && CheckNeutral(forward_neutral, backward_neutral)) {
            Log::Correct("Correct neutral test: passed");
        } else {
            Log::Error("Correct neutral test: failed");
        }
    }

    Structure GenerateCorrectStructure(
            AESLib::AES aes, AESLib::Status h_n,
            AESLib::Status status_13,
            AESLib::Status status_19
    ) {
        using namespace AESLib;
        Word w[32] = {};
        aes.ReadW(w);

        Status temp_status = {};
        temp_status.value[1][1] = status_13.value[1][1];
        for (int i = 0; i < 4; i++) {
            temp_status.value[i][1] ^= ByteInWord(w[13], i);
        }
        temp_status.InvMixColumns();
        Word const_1 = WordByByte(
                0,
                temp_status.value[1][1],
                temp_status.value[2][1],
                temp_status.value[3][1]
        );

        Status status_20 = status_19;
        for (int i = 0; i < 4; i++) {
            status_20.value[i][(4 - i) & 3] = 0;
        }
        status_20.MixColumns();

        return {
                h_n,
                w[12] ^ w[13],
                w[14],
                w[15],
                (Word) status_13.value[2][2] << 8 | status_13.value[3][3],
                const_1,
                (Word) status_20.value[0][0] << 8 | status_20.value[2][0],
                (Word) status_20.value[1][1] << 8 | status_20.value[3][1],
                (Word) status_20.value[0][2] << 8 | status_20.value[2][2],
                (Word) status_20.value[1][3] << 8 | status_20.value[3][3]
        };
    }

    void Test() {
        using namespace AESLib;
        using namespace std;

        Byte key[16] = {
                0x2b, 0x7e, 0x15, 0x16,
                0x28, 0xae, 0xd2, 0xa6,
                0xab, 0xf7, 0x15, 0x88,
                0x09, 0xcf, 0x4f, 0x3c,
        };
        AES aes(key, 4, 7);
        Status plaintext = Status(std::initializer_list<Byte>(
                {
                        0x32, 0x88, 0x31, 0xe0,
                        0x43, 0x5a, 0x31, 0x37,
                        0xf6, 0x30, 0x98, 0x07,
                        0xa8, 0x8d, 0xa2, 0x34,
                }
        ));
        Status h_n = aes.CompressionFunction(plaintext);
        Status status_13 = Status(std::initializer_list<Byte>{
                0x48, 0x67, 0x4d, 0xd6,
                0x6c, 0x1d, 0xe3, 0x5f,
                0x4e, 0x9d, 0xb1, 0x58,
                0xee, 0x0d, 0x38, 0xe7,
        });
        Status status_19 = Status(std::initializer_list<Byte>{
                0xe1, 0xe8, 0x35, 0x97,
                0xfb, 0xc8, 0x6c, 0x4f,
                0x96, 0xae, 0xd2, 0xfb,
                0x7c, 0x9b, 0xba, 0x53,
        });

        Structure structure = GenerateCorrectStructure(aes, h_n, status_13, status_19);
        structure.Test(aes, 0x481d3e, 0x7cae6c97);
    }

    void Attack(AESLib::Status h_n) {
        using namespace AESLib;
        using namespace std;
        Structure structure(h_n);
        Result result = structure.Compute();
        if (not(result.backward_neutral == 0 && result.forward_neutral == 0)) {
            stringstream ss;
            ss.str("");
            ss << "Found a solution!" << endl
               << "Forward neutral: " << hex << result.forward_neutral << endl
               << "Backward neutral: " << hex << result.backward_neutral << endl;
            Log::Correct(ss.str());
        }
    }
}
