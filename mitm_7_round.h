#ifndef AESHASHMITM_MITM_7_ROUND_H
#define AESHASHMITM_MITM_7_ROUND_H

#include "aes.h"

namespace MITM7Round {
    struct ChunkResult {
        AESLib::Byte neutral;
        AESLib::Word match;

        bool operator<(ChunkResult y) const;
    };

    class Structure {
        AESLib::AES aes;
        AESLib::Status h_n;

        AESLib::Word const_1 = 0;
        AESLib::Word const_2 = 0;
        AESLib::Status backward_start;
        AESLib::Status forward_start;
    public:
        Structure(AESLib::AES aes_, AESLib::Status h_n_);

        Structure(AESLib::AES aes_, AESLib::Status h_n_, AESLib::Word const_1_, AESLib::Word const_2_,
                  AESLib::Status backward_start_);

        void Init();

        [[nodiscard]] AESLib::Status GetForwardNeutral(AESLib::Byte neutral_byte) const;

        [[nodiscard]] AESLib::Word CalculateBackwardBytes(AESLib::Byte neutral_byte) const;

        [[nodiscard]] AESLib::Status GetBackwardNeutral(AESLib::Byte neutral_byte) const;

        [[nodiscard]] AESLib::Status ComputePlaintext(AESLib::Status status) const;

        [[nodiscard]] AESLib::Status ComputeStart(AESLib::Byte neutral_1, AESLib::Byte neutral_2) const;

        [[nodiscard]] AESLib::Status ForwardComputation(AESLib::Status status) const;

        [[nodiscard]] AESLib::Status BackwardComputation(AESLib::Status status) const;

        [[nodiscard]] bool CheckPlaintext(AESLib::Status plaintext) const;

        AESLib::Status Computation();

        [[nodiscard]] static AESLib::Byte ForwardMatch(AESLib::Status status, int col);

        [[nodiscard]] static AESLib::Word ForwardMatch(AESLib::Status status);

        [[nodiscard]] static AESLib::Byte BackwardMatch(AESLib::Status status, int col);

        [[nodiscard]] static AESLib::Word BackwardMatch(AESLib::Status status);
    };

    [[nodiscard]] bool PartialMatch(const AESLib::Status &x, const AESLib::Status &y);

    void ShowCorrectStructure(AESLib::AES aes, AESLib::Status plaintext, AESLib::Status h_n);

    void Attack(AESLib::AES aes, AESLib::Status h_n, int search_number, bool &success_flag);

    void Run();

    void Test();
}

#endif //AESHASHMITM_MITM_7_ROUND_H
