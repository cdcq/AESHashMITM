#ifndef AESHASHMITM_LOG_H
#define AESHASHMITM_LOG_H

#include <string>

namespace Log {
    void PrintTime();

    void Normal(const std::string &msg);

    void Warning(const std::string &msg);

    void Error(const std::string &msg);

    void Correct(const std::string &msg);
}

#endif //AESHASHMITM_LOG_H
