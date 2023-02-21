#include "mitm_7_round.h"

#include "aes.h"
#include "log.h"
#include <random>
#include <set>
#include <sstream>
#include <thread>
#include <vector>

namespace MITM7Round {

    bool ChunkResult::operator<(MITM7Round::ChunkResult y) const {
        return match < y.match;
    }

    Structure::Structure(AESLib::AES aes_, AESLib::Status h_n_) {
        aes = aes_;
        h_n = h_n_;

        Init();
    }

    Structure::Structure(AESLib::AES aes_, AESLib::Status h_n_, AESLib::Word const_1_, AESLib::Word const_2_,
                         AESLib::Status backward_start_) {
        aes = aes_;
        h_n = h_n_;
        const_1 = const_1_;
        const_2 = const_2_;
        backward_start = backward_start_;

        forward_start = backward_start;
        aes.AddRoundKey(forward_start, 4);
        forward_start.SubBytes();
        forward_start.ShiftRows();
    }

    void Structure::Init() {
        using namespace AESLib;
        using namespace std;

        random_device rd;
        mt19937 mt(rd());

        const_1 = mt() & 0x00ffffff;
        const_2 = mt() & 0x0000ffff;
        backward_start = Status(initializer_list<Word>{
                static_cast<unsigned int>(mt()),
                static_cast<unsigned int>(mt()),
                static_cast<unsigned int>(mt()),
                static_cast<unsigned int>(mt())
        });

        // These codes are for ensuring the constraints of neutral bytes correct.
        Status temp = {};
        for (int i = 0; i < 4; i++) {
            temp.value[i][0] = ByteInWord(const_1, i);
        }
        temp.MixColumns();
        for (int i = 0; i < 4; i++) {
            backward_start.value[i][0] = temp.value[i][0];
        }
        // Attention, here couldn't fill 0 easily.
        temp = GetBackwardNeutral(0);
        backward_start.value[0][3] = temp.value[0][3];
        backward_start.value[2][1] = temp.value[2][1];
        backward_start.value[3][2] = temp.value[3][2];

        // As long as the forward neutral and backward neutral are always legal,
        // there is no need to care about the other neutral bytes when
        // computing forward and backward match.

        forward_start = backward_start;
        aes.AddRoundKey(forward_start, 4);
        forward_start.SubBytes();
        forward_start.ShiftRows();
    }

    AESLib::Status Structure::GetForwardNeutral(AESLib::Byte neutral_byte) const {
        using namespace AESLib;
        Status temp = {};
        for (int i = 1; i < 4; i++) {
            temp.value[i][0] = ByteInWord(const_1, i);
        }
        temp.value[0][0] = neutral_byte;
        temp.MixColumns();

        aes.AddRoundKey(temp, 4);
        temp.SubBytes();
        temp.ShiftRows();

        return temp;
    }

    inline AESLib::Word Structure::CalculateBackwardBytes(AESLib::Byte neutral_byte) const {
        using namespace AESLib;
        Byte c_1 = const_2 >> 8 & 0xff;
        Byte c_2 = const_2 & 0xff;
        return (GFMul(0xd1, neutral_byte) ^ c_1) << 8 |
               (GFMul(0x69, neutral_byte) ^ c_2);
    }

    inline AESLib::Status Structure::GetBackwardNeutral(AESLib::Byte neutral_byte) const {
        AESLib::Word backward_bytes = CalculateBackwardBytes(neutral_byte);
        AESLib::Status temp = {};
        temp.value[0][3] = neutral_byte;
        temp.value[2][3] = backward_bytes >> 8 & 0xff;
        temp.value[3][3] = backward_bytes & 0xff;

        temp.InvShiftRows();
        temp.InvSubBytes();
        aes.AddRoundKey(temp, 4);

        return temp;
    }

    inline AESLib::Status Structure::ComputePlaintext(AESLib::Status status) const {
        status.MixColumns();
        aes.AddRoundKey(status, 5);
        aes.Round(status, 6);
        aes.Round(status, 7);
        status += h_n;
        return status;
    }


    AESLib::Status Structure::ComputeStart(AESLib::Byte neutral_1, AESLib::Byte neutral_2) const {
        using namespace AESLib;
        Status start = forward_start;
        Status forward_neutral = GetForwardNeutral(neutral_1);
        for (int j = 0; j < 4; j++) {
            int k = (4 - j) & 3;
            start.value[j][k] = forward_neutral.value[j][k];
        }
        Word backward_bytes = CalculateBackwardBytes(neutral_2);
        start.value[0][3] = neutral_2;
        start.value[2][3] = backward_bytes >> 8 & 0xff;
        start.value[3][3] = backward_bytes & 0xff;
        return start;
    }

    inline AESLib::Status Structure::ForwardComputation(AESLib::Status status) const {
        status = ComputePlaintext(status);
        aes.AddRoundKey(status, 0);
        aes.Round(status, 1);
        status.SubBytes();
        status.ShiftRows();
        return status;
    }

    inline AESLib::Status Structure::BackwardComputation(AESLib::Status status) const {
        status.InvMixColumns();
        status.InvShiftRows();
        status.InvSubBytes();
        aes.InvRound(status, 3);
        aes.AddRoundKey(status, 2);
        return status;
    }

    inline AESLib::Byte Structure::ForwardMatch(AESLib::Status status, int col) {
        using namespace AESLib;
        static const int row1[4] = {0, 1, 0, 1};
        static const int row2[4] = {2, 3, 2, 3};
        static const Byte factor1[4] = {0xd, 0xd, 0xe, 0xe};
        static const Byte factor2[4] = {0xe, 0xe, 0xd, 0xd};
        return GFMul(factor1[col], status.value[row1[col]][col])
               ^ GFMul(factor2[col], status.value[row2[col]][col]);
    }

    AESLib::Word Structure::ForwardMatch(AESLib::Status status) {
        AESLib::Word ret = 0;
        for (int i = 0; i < 4; i++) {
            ret <<= 8;
            ret |= ForwardMatch(status, i);
        }
        return ret;
    }

    AESLib::Byte Structure::BackwardMatch(AESLib::Status status, int col) {
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

    AESLib::Word Structure::BackwardMatch(AESLib::Status status) {
        AESLib::Word ret = 0;
        for (int i = 0; i < 4; i++) {
            ret <<= 8;
            ret |= BackwardMatch(status, i);
        }
        return ret;
    }

    inline bool Structure::CheckPlaintext(AESLib::Status plaintext) const {
        return PartialMatch(aes.CompressionFunction(plaintext), h_n);
    }

    AESLib::Status Structure::Computation() {
        using namespace AESLib;
        using namespace std;

        multiset<ChunkResult> forward_results = {};
        for (int i = 0; i < 0xff; i++) {
            Status forward_neutral = GetForwardNeutral((Byte) i);
            for (int j = 0; j < 4; j++) {
                int k = (4 - j) & 3;
                forward_start.value[j][k] = forward_neutral.value[j][k];
            }
            Status temp = ForwardComputation(forward_start);
            forward_results.insert(ChunkResult(
                    {
                            (Byte) i,
                            ForwardMatch(temp)
                    }
            ));
        }

        for (int i = 0; i < 0xff; i++) {
            Status backward_neutral = GetBackwardNeutral((Byte) i);
            backward_start.value[0][3] = backward_neutral.value[0][3];
            backward_start.value[2][1] = backward_neutral.value[2][1];
            backward_start.value[3][2] = backward_neutral.value[3][2];
            Status temp = BackwardComputation(backward_start);
            ChunkResult backward_result = {
                    (Byte) i,
                    BackwardMatch(temp)
            };
            auto iter = forward_results.lower_bound(backward_result);
            for (; iter != forward_results.end() &&
                   iter->match == backward_result.match; iter++) {
                Status start = ComputeStart(iter->neutral, (Byte) i);
                Status plaintext = ComputePlaintext(start);
                stringstream ss;
                ss << endl << aes.CompressionFunction(plaintext).ToString();
                Log::Normal(ss.str());
                if (CheckPlaintext(plaintext)) {
                    return plaintext;
                }
            }
        }

        return {};
    }

    bool PartialMatch(const AESLib::Status &x, const AESLib::Status &y) {
        const int byte_count = 1;
        for (int i = 0; i < byte_count; i++) {
            if (x.value[i][0] != y.value[i][0]) {
                return false;
            }
        }
        return true;
    }

    void Attack(AESLib::AES aes, AESLib::Status h_n, int search_number, bool &success_flag) {
        using namespace AESLib;
        using namespace std;
        Structure structure(aes, h_n);
        Status temp = structure.Computation();
        if (not(temp == Status())) {
            stringstream ss;
            ss.str("");
            ss << "Found a solution! It spends " << search_number << " search to find."
               << "Plaintext:" << endl
               << temp.ToString()
               << "H_n:" << endl
               << aes.CompressionFunction(temp).ToString();
            Log::Correct(ss.str());
            success_flag = true;
        }
    }

    void Run() {
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
        stringstream ss;
        ss << "Search started." << endl << "The goal is:" << endl
           << h_n.ToString();
        Log::Normal(ss.str());

        ShowCorrectStructure(aes, plaintext, h_n);

        thread threads[8];
        bool success_flag = false;
        for (int i = 0;; i += 8) {
            if (i % 10000 == 0) {
                ss.str("");
                ss << i << " structures have been tested.";
                Log::Normal(ss.str());
            }
            for (auto & j : threads) {
                j = thread(Attack, aes, h_n, i, ref(success_flag));
            }
            for (auto & thread : threads) {
                thread.join();
            }
            if (success_flag) {
                break;
            }
        }
    }

    void ShowCorrectStructure(AESLib::AES aes, AESLib::Status plaintext, AESLib::Status h_n) {
        using namespace AESLib;
        using namespace std;

        Status temp = plaintext;
        aes.AddRoundKey(temp, 0);
        aes.Round(temp, 1);
        aes.Round(temp, 2);
        aes.Round(temp, 3);
        temp.SubBytes();
        temp.ShiftRows();
        Byte correct_neutral_1 = temp.value[0][0];
        Word correct_const_1 = 0;
        for (int i = 1; i < 4; i++) {
            correct_const_1 <<= 8;
            correct_const_1 |= temp.value[i][0];
        }
        temp.MixColumns();
        Status correct_start = temp;
        aes.AddRoundKey(temp, 4);
        temp.SubBytes();
        temp.ShiftRows();
        Byte correct_neutral_2 = temp.value[0][3];
        Byte c_1 = temp.value[0][3] ^ GFMul(3, temp.value[2][3]) ^ temp.value[3][3];
        Byte c_2 = GFMul(3, temp.value[0][3]) ^ temp.value[2][3] ^ GFMul(2, temp.value[3][3]);
        Word correct_const_2 = (GFMul(0xb9, c_1) ^ GFMul(0xd1, c_2)) << 8 |
                               (GFMul(0xd1, c_1) ^ GFMul(0x68, c_2));
        Structure correct_structure(aes, h_n,
                                    correct_const_1, correct_const_2,
                                    correct_start);

        Status correct_res = correct_structure.Computation();
        Status correct_h_n = aes.CompressionFunction(correct_res);
        stringstream ss;
        ss << "Here are the correct structure." << endl
           << "Neutral 1: " << hex << (int) correct_neutral_1 << " "
           << "Neutral 2: " << hex << (int) correct_neutral_2 << endl
           << "Const value 1: " << hex << correct_const_1 << endl
           << "Const value 2: " << hex << correct_const_2 << endl
           << "Start:" << endl
           << correct_start.ToString()
           << "H_n:" << endl
           << correct_h_n.ToString()
           << "Result:" << endl
           << correct_res.ToString();
        Log::Normal(ss.str());
    }

    void Test() {
        using namespace AESLib;
        using namespace std;
        Status before_match(std::initializer_list<Byte>(
                {
                        0x49, 0x45, 0x7f, 0x77,
                        0xdb, 0x39, 0x02, 0xde,
                        0x87, 0x53, 0xd2, 0x96,
                        0x3b, 0x89, 0xf1, 0x1a,
                }
        ));
        Status after_match = before_match;
        after_match.MixColumns();
        if (Structure::ForwardMatch(before_match) == Structure::BackwardMatch(after_match)) {
            Log::Correct("Match test: passed");
        } else {
            stringstream ss;
            ss << "Match test: failed" << endl
               << hex << Structure::ForwardMatch(before_match) << " "
               << hex << Structure::BackwardMatch(after_match) << endl;
            Log::Error(ss.str());
        }

        bool backward_neutral_test = true;
        for (int c_1 = 0; c_1 < 0xff; c_1++) {
            for (int c_2 = 0; c_2 < 0xff; c_2++) {
                for (int a_0 = 0; a_0 < 0xff; a_0++) {
                    Byte a_2 = GFMul(0xb9, c_1) ^ GFMul(0xd1, c_2) ^ GFMul(0xd1, a_0);
                    Byte a_3 = GFMul(0xd1, c_1) ^ GFMul(0x68, c_2) ^ GFMul(0x69, a_0);
                    if ((a_0 ^ GFMul(3, a_2) ^ a_3) == c_1 &&
                        (GFMul(3, a_0) ^ a_2 ^ GFMul(2, a_3) == c_2)) {
                        continue;
                    } else {
                        backward_neutral_test = false;
                        break;
                    }
                }
            }
        }
        if (backward_neutral_test) {
            Log::Correct("Backward neutral factor correct.");
        } else {
            Log::Error("Backward neutral factor wrong.");
        }
    }
}
