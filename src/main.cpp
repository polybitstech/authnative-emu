//
// Created by wane on 26. 4. 13..
//

#include <cstdint>
#include <iostream>
#include <ostream>
#include <vector>
#include <Windows.h>

using initialize_fn_t = uint32_t(*)();
using sign_fn_t = void(*)(uint8_t *in_buf, uint32_t in_len, uint8_t *out_buf, uint32_t out_len);
using unload_fn_t = void(*)();

int main() {
    const HMODULE h = LoadLibraryW(L"authnative_emu.dll");
    if (!h)
        return 1;

    const auto init_fn = reinterpret_cast<initialize_fn_t>(GetProcAddress(h, "Initialize"));
    const auto sign_fn = reinterpret_cast<sign_fn_t>(GetProcAddress(h, "Sign"));
    const auto unload_fn = reinterpret_cast<unload_fn_t>(GetProcAddress(h, "Unload"));

    if (!init_fn || !sign_fn || !unload_fn)
        return 1;

    const uint32_t ret = init_fn();
    std::cout << "ret: " << ret << std::endl;

    std::string input;
    std::vector<uint8_t> output(10240);
    while (std::cin >> input) {
        sign_fn(reinterpret_cast<uint8_t *>(input.data()), input.size(), reinterpret_cast<uint8_t *>(output.data()),
                output.size());
        for (size_t i = output.size() - 1;; i--) {
            if (output[i] == '1') { // Sign always ends with '01'
                output.resize(i + 1);
                break;
            }
            if (i == 0) {
                throw std::runtime_error("What?");
            }
        }
        std::cout << std::string(reinterpret_cast<char *>(output.data()), output.size()) << std::endl;
    }

    unload_fn();
    FreeLibrary(h);

    std::cout << "Bye!" << std::endl;

    return 0;
}
