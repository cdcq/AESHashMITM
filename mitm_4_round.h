#ifndef AESHASHMITM_MITM_4_ROUND_H
#define AESHASHMITM_MITM_4_ROUND_H

#include "aes.h"

namespace MITM4Round {
    struct ChunkResult {
        AESLib::Byte neutral;
        AESLib::Word match;

        ChunkResult(AESLib::Byte neutral_, AESLib::Byte b10, AESLib::Byte b32);

        bool operator<(ChunkResult y) const;
    };

    class Structure {
        AESLib::AES aes;
        AESLib::Status h_n;
        AESLib::Status start;
    public:
        Structure(AESLib::AES aes_, AESLib::Status h_n_);
        Structure(AESLib::AES aes_, AESLib::Status h_n_, AESLib::Status start_);

        void StartInit();

        [[nodiscard]] AESLib::Status ComputePlaintext(AESLib::Status status) const;

        [[nodiscard]] AESLib::Status ForwardComputation(AESLib::Status status) const;

        [[nodiscard]] static AESLib::Status BackwardComputation(AESLib::Status status);

        bool CheckPlaintext(AESLib::Status plaintext);

        AESLib::Status Computation();
    };

    bool PartialMatch(const AESLib::Status &x, const AESLib::Status &y);

    void ShowCorrectStructure(AESLib::AES aes, AESLib::Status plaintext, AESLib::Status h_n);

    void Run();
}

#endif //AESHASHMITM_MITM_4_ROUND_H
