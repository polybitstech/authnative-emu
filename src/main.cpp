//
// Created by wane on 26. 4. 13..
//

#include <cstdint>
#include <iostream>
#include <ostream>
#include <Windows.h>

using initialize_fn_t = uint32_t(*)();

int main() {

    const HMODULE h = LoadLibraryW(L"authnative_emu.dll");
    if (!h)
        return 1;

    const auto fn = reinterpret_cast<initialize_fn_t>(GetProcAddress(h, "Initialize"));
    if (!fn)
        return 1;

    const uint32_t ret = fn();
    std::cout << "ret: " << ret << std::endl;

    // Wait until input
    std::cin.get();

    return 0;
}