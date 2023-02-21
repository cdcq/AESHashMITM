#include "aes.h"
#include "log.h"
#include "mitm_4_round.h"
#include "mitm_7_round.h"
#include <iostream>

int main() {
    using namespace std;
    using namespace Log;
    using namespace AESLib;
    MITM7Round::Run();
    return 0;
}
