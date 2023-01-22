#include "mitm_4_round.h"

#include "aes.h"
#include <random>

namespace MITM4Round {
    void structure(const AESLib::AES &aes, AESLib::Status h_n) {
        using namespace AESLib;
        using namespace std;

        random_device rd;
        mt19937 mt(rd());
        Status start(initializer_list<Word>{mt(), mt(), mt(), mt()});

        start.print();
    }

    void run() {
        using namespace AESLib;

        Byte key[16] = {
                0x2b, 0x7e, 0x15, 0x16,
                0x28, 0xae, 0xd2, 0xa6,
                0xab, 0xf7, 0x15, 0x88,
                0x09, 0xcf, 0x4f, 0x3c,
        };
        AES aes(key);

        Status h_n(std::initializer_list<Byte>(
                {
                        0x01, 0x23, 0x45, 0x67,
                        0x89, 0xab, 0xcd, 0xef,
                        0x00, 0x22, 0x44, 0x88,
                        0x99, 0xbb, 0xdd, 0xff,
                }
        ));

        structure(aes, h_n);
    }
}
