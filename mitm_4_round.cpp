#include "mitm_4_round.h"

#include "aes.h"
#include "log.h"
#include <random>
#include <set>
#include <sstream>

namespace MITM4Round {
    ChunkResult::ChunkResult(AESLib::Byte neutral_, AESLib::Byte b10, AESLib::Byte b32) {
        neutral = neutral_;
        match = (AESLib::Word) b10 << 8 | b32;
    }

    bool ChunkResult::operator<(ChunkResult y) const {
        return match < y.match;
    }

    Structure::Structure(AESLib::AES aes_, AESLib::Status h_n_) {
        aes = aes_;
        h_n = h_n_;
        StartInit();
    }

    Structure::Structure(AESLib::AES aes_, AESLib::Status h_n_, AESLib::Status start_) {
        aes = aes_;
        h_n = h_n_;
        start = start_;
    }

    void Structure::StartInit() {
        using namespace AESLib;
        using namespace std;

        random_device rd;
        mt19937 mt(rd());
        start = Status(initializer_list<Word>{
                static_cast<unsigned int>(mt()),
                static_cast<unsigned int>(mt()),
                static_cast<unsigned int>(mt()),
                static_cast<unsigned int>(mt())
        });
    }

    AESLib::Status Structure::ComputePlaintext(AESLib::Status status) const {
        aes.AddRoundKey(status, 2);
        aes.Round(status, 3);
        status.SubBytes();
        status.ShiftRows();
        aes.AddRoundKey(status, 4);
        status += h_n;
        return status;
    }

    AESLib::Status Structure::ForwardComputation(AESLib::Status status) const {
        status = ComputePlaintext(status);
        aes.AddRoundKey(status, 0);
        aes.Round(status, 1);
        return status;
    }

    AESLib::Status Structure::BackwardComputation(AESLib::Status status) {
        status.InvMixColumns();
        status.InvShiftRows();
        status.InvSubBytes();
        return status;
    }

    inline bool Structure::CheckPlaintext(AESLib::Status status) {
        return PartialMatch(aes.CompressionFunction(status), h_n);
        // return aes.CompressionFunction(status) == h_n;
    }

    AESLib::Status Structure::Computation() {
        using namespace AESLib;
        using namespace std;

        multiset<ChunkResult> forward_results{};
        Status temp;
        for (int i = 0; i < 0xff; i++) {
            start.value[0][0] = (Byte) i;
            temp = ForwardComputation(start);
            forward_results.insert(ChunkResult(
                    {
                            (Byte) i,
                            temp.value[1][0],
                            temp.value[3][2]
                    }
            ));
        }

        for (int i = 0; i < 0xff; i++) {
            start.value[0][3] = (Byte) i;
            temp = BackwardComputation(start);
            ChunkResult backward_result = {
                    (Byte) i,
                    temp.value[1][0],
                    temp.value[3][2]
            };
            auto iter = forward_results.lower_bound(backward_result);
            for (; iter != forward_results.end() &&
                   iter->match == backward_result.match; iter++) {
                start.value[0][0] = iter->neutral;
                start.value[0][3] = (Byte) i;
                Status plaintext = ComputePlaintext(start);
                if (CheckPlaintext(plaintext)) {
                    return plaintext;
                }
            }
        }
        return {};
    }

    bool PartialMatch(const AESLib::Status &x, const AESLib::Status &y) {
        for (int i = 0; i < 1; i++) {
            if (x.value[i][0] != y.value[i][0]) {
                return false;
            }
        }
        return true;
    }

    void ShowCorrectStructure(AESLib::AES aes, AESLib::Status plaintext, AESLib::Status h_n) {
        using namespace AESLib;
        using namespace std;
        Status correct_start = plaintext;
        aes.AddRoundKey(correct_start, 0);
        aes.Round(correct_start, 1);
        correct_start.SubBytes();
        correct_start.ShiftRows();
        correct_start.MixColumns();
        Structure correct_structure(aes, h_n, correct_start);
        Status correct_res = correct_structure.Computation();
        Status correct_h_n = aes.CompressionFunction(correct_res);
        stringstream ss;
        ss << "Here are the correct structure." << endl
           << "Start:" << endl
           << correct_start.ToString()
           << "H_n:" << endl
           << correct_h_n.ToString()
           << "Result:" << endl
           << correct_res.ToString();
        Log::Normal(ss.str());
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
        AES aes(key, 4, 4);

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

        Status zero_status = {};
        for (int i = 0;; i++) {
            if (i % 10000 == 0) {
                ss.str("");
                ss << i << " structures have been tested.";
                Log::Normal(ss.str());
            }
            Structure structure(aes, h_n);
            Status temp = structure.Computation();
            if (not(temp == zero_status)) {
                ss.str("");
                ss << "Found a solution! It spends " << i << " search to find." << endl
                   << "Plaintext:" << endl
                   << temp.ToString()
                   << "H_n:" << endl
                   << aes.CompressionFunction(temp).ToString();
                Log::Correct(ss.str());
                break;
            }
        }
    }
}
