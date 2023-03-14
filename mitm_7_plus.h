#ifndef AESHASHMITM_MITM_7_PLUS_H
#define AESHASHMITM_MITM_7_PLUS_H

#include "aes.h"

namespace MITM7Plus {
    struct ChunkResult {
        AESLib::Word neutral;   // The value of #12[0], #12[5] and #k3[7].
        AESLib::Word match;     // The calculated match value of 3 columns.

        bool operator<(ChunkResult y) const;
    };

    struct InitialStructure {
        AESLib::AES aes;
        AESLib::Status forward_start;
    };

    struct Result {
        AESLib::Word forward_neutral;
        AESLib::Word backward_neutral;
    };

    class Structure {
        AESLib::Status h_n;

        AESLib::Word const_key[3] = {}; // Constant materials in the key state.
        AESLib::Word const_0 = 0;       // 2 bytes values for #12[10, 15].
        AESLib::Word const_1 = 0;       // 3 bytes values for impacts from #12[5] and k3[4, 5, 6, 7] on #11[5, 6, 7].
        AESLib::Word const_2[4] = {};   // 8 bytes values for impacts from #19[1, 2, 3; ...] on #20[0, 2; ...].

        void Init();

        [[nodiscard]] AESLib::Word CalculateNeutralKey(AESLib::Byte neutral_1, AESLib::Byte neutral_2) const;

        [[nodiscard]] AESLib::AES InvKeyGen(AESLib::Word neutral_key) const;

        [[nodiscard]] AESLib::Status CalculateForwardStart(AESLib::Word neutral) const;

        [[nodiscard]] InitialStructure CreateInitialStructure(
                AESLib::Word forward_neutral,
                AESLib::Word backward_neutral
        ) const;

        [[nodiscard]] AESLib::Word ForwardComputation(AESLib::Word neutral) const;

        [[nodiscard]] static AESLib::Byte ForwardMatch(const AESLib::Status &status, int col);

        [[nodiscard]] static AESLib::Word ForwardMatch(const AESLib::Status &status);

        [[nodiscard]] AESLib::Word BackwardComputation(AESLib::Word neutral) const;

        [[nodiscard]] static AESLib::Byte BackwardMatch(const AESLib::Status &status, int col);

        [[nodiscard]] static AESLib::Word BackwardMatch(const AESLib::Status &status);

        [[nodiscard]] bool CheckNeutral(
                AESLib::Word forward_neutral,
                AESLib::Word backward_neutral
        ) const;

    public:
        explicit Structure(AESLib::Status h_n_);

        Structure(
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
        );

        Result Compute();

        void Test(
                const AESLib::AES &aes,
                AESLib::Word forward_neutral,
                AESLib::Word backward_neutral
        );
    };

    void Test();

    void Attack();
}

#endif //AESHASHMITM_MITM_7_PLUS_H
