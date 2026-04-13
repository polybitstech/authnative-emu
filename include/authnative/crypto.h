//
// Created by wane on 26. 4. 13..
//

#pragma once

#include "utils.h"

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

inline bytes md5(const bytes& b)
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
        BCRYPT_MD5_ALGORITHM,
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
        // ReSharper disable once CppFunctionResultShouldBeUsed
        BCryptDestroyHash(hash);
    if (alg)
        // ReSharper disable once CppFunctionResultShouldBeUsed
        BCryptCloseAlgorithmProvider(alg, 0);

    if (status < 0)
        return {};

    return digest;
}