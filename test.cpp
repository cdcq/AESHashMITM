#include "aes.h"
#include "calculator.h"
#include "log.h"
#include "mitm_4_round.h"
#include "mitm_7_round.h"
#include "mitm_7_plus.h"
#include <iostream>

int main() {
    using namespace std;
    using namespace Log;
    using namespace AESLib;
    using namespace Calculator;
    MITM7Plus::Test();
    return 0;
}
