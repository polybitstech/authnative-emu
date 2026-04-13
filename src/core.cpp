//
// Created by wane on 26. 4. 13..
//
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <map>
#include <mutex>
#include <numeric>
#include <ranges>

#include <shlobj.h>

#include "authnative/constants.h"
#include "authnative/crypto.h"
#include "authnative/utils.h"

#define AUTHNATIVE_API __declspec(dllexport)

struct AuthContext;

class FDWorker {
public:
    explicit FDWorker(AuthContext* ctx) : _ctx(ctx) {}
    ~FDWorker() {
        stop(); // For safety..
    }

    void start() {
        _stop_requested = false;
        _thread = std::thread(&FDWorker::fn, this, _ctx);
    }

    void stop() {
        _stop_requested = true;
        if (_thread.joinable()) {
            _thread.join();
        }
    }

private:
    void fn(AuthContext* ctx) const;

    AuthContext* _ctx;
    std::atomic<bool> _stop_requested{false};
    std::thread _thread;
};

struct AuthContext {
    std::wstring lazer_local_path;
    std::wstring lazer_roaming_path;

    // vector because ordering is important.
    std::vector<std::pair<std::string, bytes> > dll_map;
    bytes dll_total_hash;

    std::map<uint32_t, bytes> hwid_artifacts;
    bytes hwid_artifacts_key;
    bytes hwid_artifacts_buf;
    bytes hwid_artifacts_enc;

    // Freedom Detection
    mutable std::mutex fd_mutex;

    uint64_t sid{0};
    bytes fd_buf;
    size_t fd_buf_off{0};
    bytes fd_lbox;
    bytes fd_sbox;
    uint32_t fd_nonce{0};

    FDWorker fd_worker{this};
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

bytes gen_hwid_file_contents() {
    const auto contents = random_bytes(0x80);
    const auto hash = crc32(contents);
    return to_le_bytes<uint32_t>(hash) + contents;
}

bool init_hwid(AuthContext *ctx) {
    const auto hwid_file_path = std::filesystem::path(ctx->lazer_roaming_path) / an_consts::hwid_file_artifact_path;
    if (!std::filesystem::exists(hwid_file_path)) {
        // Make one
        const auto contents = gen_hwid_file_contents();
        std::filesystem::create_directories(hwid_file_path.parent_path());
        std::ofstream f(hwid_file_path, std::ios::binary);
        if (!f)
            return false;
        f.write(reinterpret_cast<const char *>(contents.data()), static_cast<std::streamsize>(contents.size()));
    }

    bytes contents(0x80);

    std::ifstream f(hwid_file_path, std::ios::binary);
    if (!f)
        return false;
    f.seekg(4, std::ios::beg); // Skip CRC32
    f.read(reinterpret_cast<char *>(contents.data()), static_cast<std::streamsize>(contents.size()));
    if (f.gcount() != static_cast<std::streamsize>(contents.size()))
        return false;

    ctx->hwid_artifacts[an_consts::hwid_file_artifact_marker] = sha1(contents);

    const auto disks = get_disks();

    std::wstring disks_concated;
    for (const auto &[manufacturer, model, serial]: disks) {
        disks_concated.append(manufacturer);
        disks_concated.append(model);
        disks_concated.append(serial);
    }

    ctx->hwid_artifacts[an_consts::hwid_disks_artifact_marker] = sha1(to_bytes(disks_concated));

    for (const auto &[marker, hash]: ctx->hwid_artifacts) {
        ctx->hwid_artifacts_buf += to_le_bytes<uint32_t>(marker) + hash;
    }
    if (ctx->hwid_artifacts_buf.size() > 0x400) {
        return false; // wtf? it will not happen.
    }
    ctx->hwid_artifacts_buf += random_bytes(0x400 - ctx->hwid_artifacts_buf.size()); // pad to 0x400 bytes

    ctx->hwid_artifacts_key = random_bytes(0x40);

    // later we use this
    ctx->hwid_artifacts_enc = bytes(0x400);
    for (size_t i = 0; i < ctx->hwid_artifacts_buf.size(); ++i) {
        ctx->hwid_artifacts_enc[i] = ctx->hwid_artifacts_buf[i] + ctx->hwid_artifacts_key[i % 0x40];
    }

    return true;
}

[[nodiscard]] uint64_t get_sid() {
    return fnv1a64(to_le_bytes<uint32_t>(GetCurrentThreadId())) ^
           get_ft_as_epoch() / 10000 ^ an_consts::sid_xor;
}

void refresh_fd(AuthContext *ctx, const uint64_t sid) {
    std::lock_guard lock(ctx->fd_mutex);

    ctx->sid = sid;
    PCG32<an_consts::pcg_increment> pcg(sid);

    ctx->fd_buf.clear();
    for ([[maybe_unused]] size_t i = 0; i < 256; i++) {
        ctx->fd_buf += to_le_bytes<uint32_t>(pcg.next());
    }
    ctx->fd_buf_off = 0;

    ctx->fd_lbox.clear();
    for ([[maybe_unused]] size_t i = 0; i < 64; i++) {
        ctx->fd_lbox += to_le_bytes<uint32_t>(pcg.next());
    }

    ctx->fd_sbox.clear();
    ctx->fd_sbox = bytes(0x100);
    std::iota(ctx->fd_sbox.begin(), ctx->fd_sbox.end(), uint8_t{0});

    for (size_t i = 0; i < 255; i++) {
        const auto x = pcg.next();
        const size_t j = x % (0x100 - i);
        std::swap(ctx->fd_sbox[255 - i], ctx->fd_sbox[j]);
    }

    ctx->fd_nonce = pcg.next();
}

void FDWorker::fn(AuthContext *ctx) const {
    auto next_perform = std::chrono::steady_clock::now();

    while (!_stop_requested) {
        Sleep(an_consts::fd_thread_sleep_interval);
        if (_stop_requested)
            break;

        if (std::chrono::steady_clock::now() >= next_perform) {
            std::lock_guard lock(ctx->fd_mutex);
            // Assume we don't AFK 200 minutes in the game
            if (ctx->fd_buf_off + 10 <= ctx->fd_buf.size()) {

                for (size_t i = 0; i < 10; i++) {
                    const uint8_t g = ctx->fd_buf[i + ctx->fd_buf_off];
                    const uint8_t k = an_consts::fd_key[i];
                    const auto neg_k = static_cast<uint8_t>(0x100 - k);
                    bytes p = to_le_bytes<uint32_t>(ctx->fd_nonce);

                    const uint8_t v1 = p[1] + p[3] * 3;
                    const uint8_t v2 = rol8(ctx->fd_sbox[neg_k ^ g ^ ctx->fd_lbox[p[0]]], p[2]);
                    ctx->fd_buf[i + ctx->fd_buf_off] = v1 ^ v2;

                    const uint8_t pnew_0 = ctx->fd_lbox[p[0]] - k;
                    const uint8_t pnew_8 = ctx->fd_sbox[p[1]] + k;
                    const uint8_t pnew_16 = ctx->fd_sbox[p[3]] ^ neg_k;
                    const uint8_t pnew_24 = ctx->fd_lbox[p[2]] ^ neg_k;

                    uint32_t pnew =
                        static_cast<uint32_t>(pnew_0) |
                        (static_cast<uint32_t>(pnew_8)  << 8) |
                        (static_cast<uint32_t>(pnew_16) << 16) |
                        (static_cast<uint32_t>(pnew_24) << 24);

                    pnew = rol32(pnew ^ ctx->fd_nonce, 7) + an_consts::fd_nonce_upadte_c;
                    ctx->fd_nonce = pnew;

                }
                ctx->fd_buf_off += 10;
            }

        } else {
            continue;
        }

        next_perform += std::chrono::milliseconds(an_consts::fd_perform_interval);
    }
}

void init_freedom_detection(AuthContext *ctx) {
    refresh_fd(ctx, 0xd58c0b234f82e21);
    ctx->fd_worker.start();
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

    init_freedom_detection(a_ctx);

    return 0;
}

extern "C" AUTHNATIVE_API void Sign(uint8_t *in_buf, uint32_t in_len, uint8_t *out_buf, uint32_t out_len) {
}

extern "C" AUTHNATIVE_API void Unload() {
}
