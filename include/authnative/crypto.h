#pragma once

#include "utils.h"

#include <array>
#include <cstdint>
#include <vector>

inline bytes random_bytes(const size_t n)
{
    bytes out(n);
    if (n == 0)
        return out;

    const NTSTATUS status = BCryptGenRandom(
        nullptr,
        out.data(),
        out.size(),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (status < 0)
        return {};

    return out;
}

static constexpr std::array<uint32_t, 256> make_crc32_table()
{
    std::array<uint32_t, 256> table{};

    for (uint32_t i = 0; i < 256; ++i)
    {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j)
        {
            if (c & 1)
                c = (c >> 1) ^ 0xEDB88320u;
            else
                c >>= 1;
        }
        table[i] = c;
    }

    return table;
}

inline uint32_t crc32(const bytes& b)
{
    static constexpr auto table = make_crc32_table();

    uint32_t crc = 0xFFFFFFFFu;

    for (const uint8_t x : b)
        crc = (crc >> 8) ^ table[(crc ^ x) & 0xFF];

    return ~crc;
}

inline uint64_t fnv1a64(const bytes& data)
{
    uint64_t hash = 0xCBF29CE484222325ULL;

    for (const uint8_t b : data)
    {
        hash ^= b;
        hash *= 0x100000001B3ULL;
    }

    return hash;
}

template <uint64_t Increment>
class PCG32
{
    static_assert((Increment & 1ULL) == 1ULL, "Increment must be odd.");

public:
    explicit PCG32(const uint64_t seed) : state_(seed) {}

    uint32_t next()
    {
        const uint64_t state = state_;

        const uint32_t out = rotr32(
            static_cast<uint32_t>((state >> 45) ^ (state >> 27)),
            static_cast<uint32_t>(state >> 59)
        );

        state_ = state_ * 0x5851F42D4C957F2DULL + Increment;
        return out;
    }

private:
    static constexpr uint32_t rotr32(const uint32_t x, uint32_t r)
    {
        r &= 31;
        return ((x >> r) | (x << ((32 - r) & 31))) & 0xFFFFFFFFu;
    }
    uint64_t state_;
};

inline bytes hash_bytes(const wchar_t* alg_id, const bytes& b)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;

    DWORD cb_data = 0;
    DWORD object_length = 0;
    DWORD hash_length = 0;

    bytes hash_object;
    bytes digest;

    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &alg,
        alg_id,
        nullptr,
        0
    );
    if (status < 0)
        return {};

    status = BCryptGetProperty(
        alg,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_length),
        sizeof(object_length),
        &cb_data,
        0
    );
    if (status < 0)
        goto cleanup;

    status = BCryptGetProperty(
        alg,
        BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hash_length),
        sizeof(hash_length),
        &cb_data,
        0
    );
    if (status < 0)
        goto cleanup;

    hash_object.resize(object_length);
    digest.resize(hash_length);

    status = BCryptCreateHash(
        alg,
        &hash,
        hash_object.data(),
        hash_object.size(),
        nullptr,
        0,
        0
    );
    if (status < 0)
        goto cleanup;

    if (!b.empty())
    {
        status = BCryptHashData(
            hash,
            const_cast<PUCHAR>(b.data()),
            b.size(),
            0
        );
        if (status < 0)
            goto cleanup;
    }

    status = BCryptFinishHash(
        hash,
        digest.data(),
        digest.size(),
        0
    );

cleanup:
    if (hash)
        BCryptDestroyHash(hash);
    if (alg)
        BCryptCloseAlgorithmProvider(alg, 0);

    if (status < 0)
        return {};

    return digest;
}

inline bytes hmac_bytes(const wchar_t* alg_id, const bytes& key, const bytes& b)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;

    DWORD cb_data = 0;
    DWORD object_length = 0;
    DWORD hash_length = 0;

    bytes hash_object;
    bytes digest;

    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &alg,
        alg_id,
        nullptr,
        BCRYPT_ALG_HANDLE_HMAC_FLAG
    );
    if (status < 0)
        return {};

    status = BCryptGetProperty(
        alg,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_length),
        sizeof(object_length),
        &cb_data,
        0
    );
    if (status < 0)
        goto cleanup;

    status = BCryptGetProperty(
        alg,
        BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hash_length),
        sizeof(hash_length),
        &cb_data,
        0
    );
    if (status < 0)
        goto cleanup;

    hash_object.resize(object_length);
    digest.resize(hash_length);

    status = BCryptCreateHash(
        alg,
        &hash,
        hash_object.data(),
        hash_object.size(),
        const_cast<PUCHAR>(key.data()),
        key.size(),
        0
    );
    if (status < 0)
        goto cleanup;

    if (!b.empty())
    {
        status = BCryptHashData(
            hash,
            const_cast<PUCHAR>(b.data()),
            b.size(),
            0
        );
        if (status < 0)
            goto cleanup;
    }

    status = BCryptFinishHash(
        hash,
        digest.data(),
        digest.size(),
        0
    );

cleanup:
    if (hash)
        BCryptDestroyHash(hash);
    if (alg)
        BCryptCloseAlgorithmProvider(alg, 0);

    if (status < 0)
        return {};

    return digest;
}

inline bytes md5(const bytes& b)
{
    return hash_bytes(BCRYPT_MD5_ALGORITHM, b);
}

inline bytes sha1(const bytes& b)
{
    return hash_bytes(BCRYPT_SHA1_ALGORITHM, b);
}

inline bytes hmac_sha1(const bytes& key, const bytes& b)
{
    return hmac_bytes(BCRYPT_SHA1_ALGORITHM, key, b);
}

// return: ciphertext || tag(16)
inline bytes aes_gcm(const bytes& key, const bytes& iv, const bytes& b)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE hkey = nullptr;

    DWORD cb_data = 0;
    DWORD object_length = 0;
    constexpr DWORD tag_length = 16;
    ULONG ciphertext_length = 0;

    bytes key_object;
    bytes ciphertext(b.size());
    bytes tag(tag_length);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = const_cast<PUCHAR>(iv.data());
    auth_info.cbNonce = static_cast<ULONG>(iv.size());
    auth_info.pbTag = tag.data();
    auth_info.cbTag = static_cast<ULONG>(tag.size());

    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &alg,
        BCRYPT_AES_ALGORITHM,
        nullptr,
        0
    );
    if (status < 0)
        return {};

    status = BCryptSetProperty(
        alg,
        BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
        (wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(wchar_t),
        0
    );
    if (status < 0)
        goto cleanup;

    status = BCryptGetProperty(
        alg,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_length),
        sizeof(object_length),
        &cb_data,
        0
    );
    if (status < 0)
        goto cleanup;

    key_object.resize(object_length);

    status = BCryptGenerateSymmetricKey(
        alg,
        &hkey,
        key_object.data(),
        key_object.size(),
        const_cast<PUCHAR>(key.data()),
        key.size(),
        0
    );
    if (status < 0)
        goto cleanup;

    status = BCryptEncrypt(
        hkey,
        const_cast<PUCHAR>(b.data()),
        b.size(),
        &auth_info,
        nullptr,
        0,
        ciphertext.data(),
        ciphertext.size(),
        &ciphertext_length,
        0
    );
    if (status < 0)
        goto cleanup;

    ciphertext.resize(ciphertext_length);

cleanup:
    if (hkey)
        BCryptDestroyKey(hkey);
    if (alg)
        BCryptCloseAlgorithmProvider(alg, 0);

    if (status < 0)
        return {};

    return ciphertext + tag;
}

// RSA public key blob import + OAEP-SHA1 encrypt
// public_blob must be a valid BCRYPT_RSAPUBLIC_BLOB of a 3072-bit key.
// return: RSA ciphertext
inline bytes rsa_3072_oaep_sha1_encrypt(const bytes& public_blob, const bytes& b)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE hkey = nullptr;

    ULONG out_len = 0;
    bytes out;

    DWORD key_bits = 0;
    DWORD cb_data = 0;

    BCRYPT_OAEP_PADDING_INFO oaep_info{};
    oaep_info.pszAlgId = const_cast<wchar_t*>(BCRYPT_SHA1_ALGORITHM);
    oaep_info.pbLabel = nullptr;
    oaep_info.cbLabel = 0;

    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &alg,
        BCRYPT_RSA_ALGORITHM,
        nullptr,
        0
    );
    if (status < 0)
        return {};

    status = BCryptImportKeyPair(
        alg,
        nullptr,
        BCRYPT_RSAPUBLIC_BLOB,
        &hkey,
        const_cast<PUCHAR>(public_blob.data()),
        public_blob.size(),
        0
    );
    if (status < 0)
        goto cleanup;

    status = BCryptGetProperty(
        hkey,
        BCRYPT_KEY_LENGTH,
        reinterpret_cast<PUCHAR>(&key_bits),
        sizeof(key_bits),
        &cb_data,
        0
    );
    if (status < 0)
        goto cleanup;

    if (key_bits != 3072)
    {
        status = STATUS_INVALID_PARAMETER;
        goto cleanup;
    }

    status = BCryptEncrypt(
        hkey,
        const_cast<PUCHAR>(b.data()),
        b.size(),
        &oaep_info,
        nullptr,
        0,
        nullptr,
        0,
        &out_len,
        BCRYPT_PAD_OAEP
    );
    if (status < 0)
        goto cleanup;

    out.resize(out_len);

    status = BCryptEncrypt(
        hkey,
        const_cast<PUCHAR>(b.data()),
        b.size(),
        &oaep_info,
        nullptr,
        0,
        out.data(),
        out.size(),
        &out_len,
        BCRYPT_PAD_OAEP
    );
    if (status < 0)
        goto cleanup;

    out.resize(out_len);

cleanup:
    if (hkey)
        // ReSharper disable once CppFunctionResultShouldBeUsed
        BCryptDestroyKey(hkey);
    if (alg)
        // ReSharper disable once CppFunctionResultShouldBeUsed
        BCryptCloseAlgorithmProvider(alg, 0);

    if (status < 0)
        return {};

    return out;
}