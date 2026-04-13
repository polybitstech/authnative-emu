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

#include "nlohmann/json.hpp"

#include "authnative/constants.h"
#include "authnative/crypto.h"
#include "authnative/utils.h"

#define AUTHNATIVE_API __declspec(dllexport)

struct AuthContext;

class FDWorker {
public:
    explicit FDWorker(AuthContext *ctx) : _ctx(ctx) {
    }

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
    void fn(AuthContext *ctx) const;

    AuthContext *_ctx;
    std::atomic<bool> _stop_requested{false};
    std::thread _thread;
};

struct AuthContext {
    std::wstring lazer_local_path;
    std::wstring lazer_roaming_path;

    // vector because ordering is important.
    std::vector<std::pair<std::string, bytes> > dll_map;
    std::vector<std::pair<bytes, bytes> > dll_map_enc;
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

            auto hash = md5(get_file_contents(file));
            ctx->dll_map.emplace_back(dll_name, hash);
            ctx->dll_map_enc.emplace_back(F_encrypt(to_bytes(dll_name)), F_encrypt(hash));

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

                    bytes p_new_b(4);
                    p_new_b[0] = ctx->fd_lbox[p[0]] - k;
                    p_new_b[1] = ctx->fd_sbox[p[1]] + k;
                    p_new_b[2] = ctx->fd_sbox[p[3]] ^ neg_k;
                    p_new_b[3] = ctx->fd_lbox[p[2]] ^ neg_k;

                    auto pnew = from_le_bytes<uint32_t>(p_new_b);
                    pnew = rol32(pnew ^ ctx->fd_nonce, 7) + an_consts::fd_nonce_update_c;

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
    refresh_fd(ctx, get_sid());
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

bytes make_2bytes(const uint32_t key, const uint16_t input) {
    const auto key_b = to_le_bytes<uint32_t>(key);
    const auto g = key_b + key_b;

    uint8_t cur = input >> 8, c1 = input & 0xFF, c2 = input >> 8;
    for (size_t i = 0; i < 8; i++) {
        const uint8_t h = g[i] ^ cur;
        if (i % 2 == 0) {
            c1 ^= h;
            cur = rol8(c1, 7);
        } else {
            c2 ^= h;
            cur = rol8(c2, 7);
        }
    }

    return {c1, c2};
}

bytes make_8bytes(const uint32_t key, const uint64_t input) {
    bytes buf(32);
    bytes main(32);
    const bytes input_b = to_le_bytes<uint64_t>(input);
    const bytes key_b = to_le_bytes<uint32_t>(key);

    for (size_t i = 0; i < 32; i++) {
        uint8_t cur;
        if (i < 4) {
            cur = input_b[i + 4];
        } else {
            cur = main[i - 4];
        }
        const size_t cidx = (i / 4 + i % 4) & 3;
        buf[i] = rol8(cur, 7) ^ key_b[cidx];
        if (i < 8) {
            main[i] = buf[i] ^ input_b[i];
        } else {
            main[i] = buf[i] ^ main[i - 8];
        }
    }
    return {main[24], main[25], main[26], main[27], main[28], main[29], main[30], main[31]};
}

bool has_ruleset_id(const bytes &bytes) {
    try {
        const auto j = nlohmann::json::parse(bytes.begin(), bytes.end());
        return j.contains("ruleset_id");
    } catch (...) {
        return false;
    }
}

bytes build_inner(AuthContext *ctx, const bytes &msg) {
    bytes payload;
    payload += to_le_bytes<uint32_t>(an_consts::inner_magic);
    payload += to_le_bytes<uint64_t>(get_ft_as_epoch());
    payload += to_le_bytes<uint32_t>(static_cast<uint32_t>(ctx->dll_map.size()));
    for (const auto &[dll_name_enc, dll_hash_enc]: ctx->dll_map_enc) {
        payload += to_le_bytes<uint32_t>(static_cast<uint32_t>(dll_name_enc.size()));
        payload += dll_name_enc;
        payload += to_le_bytes<uint32_t>(static_cast<uint32_t>(dll_hash_enc.size()));
        payload += dll_hash_enc;
    }
    payload += to_le_bytes<uint32_t>(static_cast<uint32_t>(ctx->hwid_artifacts.size()));
    payload += ctx->hwid_artifacts_enc;
    payload += ctx->hwid_artifacts_key;


    const size_t mt_key_length = random_u32() % an_consts::inner_mt_key_l_divider + an_consts::inner_mt_key_l_adder;
    const bytes mt_key = random_bytes(mt_key_length);
    payload += to_le_bytes<uint32_t>(static_cast<uint32_t>(mt_key_length));
    payload += mt_key;

    // we do manual `from_le_bytes` here because mt_key is more than 4 bytes
    const uint32_t key_first = mt_key[0] | (mt_key[1] << 8) | (mt_key[2] << 16) | (mt_key[3] << 24);
    const uint32_t a = static_cast<uint32_t>(from_le_bytes<uint16_t>(random_bytes(2)) << 16) |
                       an_consts::inner_a_lower4;

    payload += to_le_bytes<uint32_t>(a);

    const uint32_t g = a ^ key_first;

    if (has_ruleset_id(msg)) {
        {
            std::lock_guard lock(ctx->fd_mutex);
            payload += make_2bytes(g, 1);
            payload += make_8bytes(g, ctx->sid);
            payload += make_8bytes(g, reinterpret_cast<uint64_t>(ctx->fd_buf.data()));
            payload += make_8bytes(g, reinterpret_cast<uint64_t>(ctx->fd_buf.data()) + ctx->fd_buf_off);
            payload += ctx->fd_buf;
        }
        refresh_fd(ctx, get_sid());
    } else {
        payload += make_2bytes(g, 0);
    }


    auto hmac = hmac_sha1(to_bytes(an_consts::inner_hmac_key), payload + msg);
    auto hmac_enc = F_encrypt(to_bytes(to_upperhex(hmac)));

    payload += to_le_bytes<uint32_t>(static_cast<uint32_t>(hmac_enc.size()));
    payload += hmac_enc;

    return payload;
}

extern "C" AUTHNATIVE_API void Sign(uint8_t *in_buf, const uint32_t in_len, uint8_t *out_buf, const uint32_t out_len) {
    const bytes in_bytes(in_buf, in_buf + in_len);
    const auto inner = build_inner(a_ctx, in_bytes);

    const auto gcm_key = random_bytes(16);
    const auto gcm_iv = random_bytes(12);

    const auto inner_enc = aes_gcm(gcm_key, gcm_iv, inner);

    static const auto blob = make_rsa_public_blob(to_bytes(an_consts::rsa_exponent_be),
                                                  to_bytes(an_consts::rsa_modulus_be));

    const auto key_iv_enc = rsa_3072_oaep_sha1_encrypt(blob, gcm_key + gcm_iv);

    const auto footer = to_upperhex(a_ctx->dll_total_hash) + to_upperhex(
                            to_le_bytes<uint32_t>(static_cast<uint32_t>(get_ft_as_epoch() / 10'000'000)));
    const auto footer_hmac = hmac_sha1(to_bytes(an_consts::footer_hmac_key), to_bytes(footer));

    const auto completed = to_upperhex(key_iv_enc) + to_upperhex(inner_enc) + footer + to_upperhex(footer_hmac) + "01";

    assert(out_len >= completed.size());
    std::memcpy(out_buf, completed.data(), completed.size());
}

extern "C" AUTHNATIVE_API void Unload() {
    a_ctx->fd_worker.stop();
    delete a_ctx;
    a_ctx = nullptr;
}
