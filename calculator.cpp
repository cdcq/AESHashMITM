#include "calculator.h"

#include "aes.h"
#include <iostream>
#include <string>

namespace Calculator {
    unsigned Hex2Int(const std::string &x) {
        return std::stoul(x, nullptr, 16);
    }

    [[noreturn]] void Run() {
        using namespace std;
        using namespace AESLib;
        for (;;) {
            cout << ">> " << flush;
            string a, b;
            cin >> a >> b;
            if (b == "-1") {
                cout << hex << (int) GFInvSlow(Hex2Int(a));
            } else if (b == "+") {
                cin >> b;
                cout << hex << (int)(Hex2Int(a) ^ Hex2Int(b));
            }
            else {
                cout << hex << (int) GFMul(Hex2Int(a), Hex2Int(b));
            }
            cout << endl;
        }
    }

    void PrintMatrix(const Matrix &matrix) {
        for (auto &i : matrix) {
            for (auto j : i) {
                std::cout << std::hex << j << " ";
            }
            std::cout << std::endl;
        }
    }

    Matrix Solve(const Matrix &matrix) {
        using namespace AESLib;
        Matrix a = matrix;
        int n = (int) a.size();
        int m = (int) a[0].size();
        if (n > m) {
            return {};
        }
        for (int i = 0; i < n; i++) {
            unsigned int k = GFInvSlow(a[i][i]);
            for (int j = i; j < m; j++) {
                a[i][j] = GFMul(a[i][j], k);
            }
            for (int l = i + 1; l < n; l++) {
                k = a[l][i];
                for(int j = i; j < m; j++) {
                    a[l][j] ^= GFMul(a[i][j], k);
                }
            }
        }
        for (int i = 0; i < n; i++) {
            for (int r = i + 1; r < n; r++) {
                unsigned int k = a[i][r];
                for (int j = r; j < m; j++) {
                    a[i][j] ^= GFMul(a[r][j], k);
                }
            }
        }
        return a;
    }
}