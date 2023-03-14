#ifndef AESHASHMITM_CALCULATOR_H
#define AESHASHMITM_CALCULATOR_H

#include <vector>

namespace Calculator {
    typedef std::vector<std::vector<unsigned int>> Matrix;

    void PrintMatrix(const Matrix &matrix);

    [[noreturn]] void Run();

    Matrix Solve(const Matrix &matrix);
}

#endif //AESHASHMITM_CALCULATOR_H
