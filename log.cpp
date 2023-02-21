#include "log.h"

#include <ctime>
#include <iostream>

namespace Log {
    void PrintTime() {
        using namespace std;
        auto time1 = time(nullptr);
        auto time2 = localtime(&time1);
        char time_str[32];
        strftime(time_str, 32, "%Y-%m-%d %H:%M:%S", time2);
        cout << time_str << " ";
    }

    void Normal(const std::string &msg) {
        PrintTime();
        std::cout << "| " << msg << std::endl;
    }

    void Warning(const std::string &msg) {
        PrintTime();
        std::cout << "| " << "\033[33m" << msg << "\033[0m" << std::endl;
    }

    void Error(const std::string &msg) {
        PrintTime();
        std::cout << "| " << "\033[31m" << msg << "\033[0m" << std::endl;
    }

    void Correct(const std::string &msg) {
        PrintTime();
        std::cout << "| " << "\033[32m" << msg << "\033[0m" << std::endl;
    }
}
