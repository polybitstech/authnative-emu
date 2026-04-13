//
// Created by wane on 26. 4. 13..
//
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <ranges>

#include <shlobj.h>

#include "authnative/constants.h"
#include "authnative/crypto.h"
#include "authnative/utils.h"

#define AUTHNATIVE_API __declspec(dllexport)

#define UNUSED(x) (void)(x)

struct AuthContext {
    std::wstring lazer_local_path;
    std::wstring lazer_roaming_path;

    std::vector<std::pair<std::string, bytes> > dll_map;
    bytes dll_total_hash;
};

AuthContext *a_ctx = nullptr;

bytes F_encrypt(const bytes &data) {
    bytes r1 = random_bytes(4);
    bytes r2 = random_bytes(4);

    if (r1.size() != 4 || r2.size() != 4)
        return {};

    bytes k(4);
    for (size_t i = 0; i < 4; ++i)
        k[i] = r1[i] ^ r2[i];

    bytes enc(data.size());
    for (size_t i = 0; i < data.size(); ++i)
        enc[i] = data[i] ^ k[i & 3];

    bytes out;
    out.reserve(4 + enc.size() + 4);

    out.insert(out.end(), r1.begin(), r1.end());
    out.insert(out.end(), enc.begin(), enc.end());
    out.insert(out.end(), r2.begin(), r2.end());

    return out;
}

///
/// The emulator assumes that the DLL files specified in `constants.h` are located in the same directory as the osu executable.
/// It also assumes that the data files are located in `%appdata%/osu`.
/// If these assumptions are not met, the emulator should not work.
///
bool init_dll_map(AuthContext *ctx) {
    const bool ok = std::ranges::all_of(
        an_consts::dll_names, [&](const char *dll_name) {
            const auto file = std::filesystem::path(ctx->lazer_local_path) / dll_name;
            if (!std::filesystem::exists(file)) {
                return false;
            }
            ctx->dll_map.emplace_back(dll_name, md5(get_file_contents(file)));
            return true;
        });
    if (!ok)
        return false;

    std::string total;
    for (const auto &v: ctx->dll_map | std::views::values) {
        total += to_upperhex(v);
    }
    ctx->dll_total_hash = md5(to_bytes(total));

    return true;
}

bool init_hwid(AuthContext *ctx) {
    return true;
}

std::wstring get_current_process_dir() {
    wchar_t buf[MAX_PATH];
    if (const DWORD len = GetModuleFileNameW(nullptr, buf, MAX_PATH); len == 0 || len == MAX_PATH) {
        return L"";
    }
    return std::filesystem::path(buf).parent_path().wstring();
}

std::wstring get_default_lazer_path() {
    wchar_t buf[MAX_PATH];
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, buf)))
        return L"";
    return (std::filesystem::path(buf) / L"osu").wstring();
}

extern "C" AUTHNATIVE_API uint32_t Initialize() {
    if (a_ctx) {
        // Already initialized..
        return 1;
    }

    a_ctx = new AuthContext();

    a_ctx->lazer_local_path = get_current_process_dir();
    a_ctx->lazer_roaming_path = get_default_lazer_path();

    std::wcout << a_ctx->lazer_local_path << std::endl;

    if (a_ctx->lazer_local_path.empty() || a_ctx->lazer_roaming_path.empty()) {
        // Couldn't get paths
        return 1;
    }

    if (!init_dll_map(a_ctx)) {
        // Couldn't initialize dll map
        return 1;
    }

    if (!init_hwid(a_ctx)) {
        // Couldn't initialize hwid
        return 1;
    }

    for (const auto &p: a_ctx->dll_map) {
        std::cout << p.first << " " << to_upperhex(p.second) << std::endl;
    }
    std::cout << "total hash: " << to_upperhex(a_ctx->dll_total_hash) << std::endl;

    return 0;
}

extern "C" AUTHNATIVE_API void Sign(uint8_t *in_buf, uint32_t in_len, uint8_t *out_buf, uint32_t out_len) {
}

extern "C" AUTHNATIVE_API void Unload() {
}
