//
// Created by wane on 26. 4. 13..
//

#pragma once

#include <string>
#include <cstdint>
#include <cstring>
#include <vector>
#include <fstream>

#include <Wbemidl.h>
#include <comdef.h>

using bytes = std::vector<uint8_t>;

inline bytes operator+(const bytes &a, const bytes &b) {
    bytes out;
    out.reserve(a.size() + b.size());

    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());

    return out;
}

inline bytes &operator+=(bytes &a, const bytes &b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

inline bytes to_bytes(const std::string &s) {
    return {s.begin(), s.end()};
}

inline bytes to_bytes(const std::wstring &s) {
    const auto *p = reinterpret_cast<const uint8_t *>(s.data());
    return {p, p + s.size() * sizeof(wchar_t)};
}

template <size_t N>
bytes to_bytes(const std::array<uint8_t, N>& a)
{
    return bytes(a.begin(), a.end());
}

template <typename T>
bytes to_le_bytes(T value)
{
    static_assert(std::is_integral_v<T>, "T must be an integral type");

    bytes out(sizeof(T));
    for (size_t i = 0; i < sizeof(T); ++i)
        out[i] = static_cast<uint8_t>(static_cast<std::make_unsigned_t<T>>(value) >> (i * 8) & 0xFF);

    return out;
}

inline std::string to_upperhex(const bytes &b) {
    static constexpr char hex[] = "0123456789ABCDEF";

    std::string out;
    out.reserve(b.size() * 2);

    for (const uint8_t v: b) {
        out.push_back(hex[v >> 4]);
        out.push_back(hex[v & 0x0F]);
    }

    return out;
}

inline bytes get_file_contents(const std::wstring &path) {
    std::ifstream f(path.c_str(), std::ios::binary);
    if (!f)
        return {};

    f.seekg(0, std::ios::end);
    const std::streamsize size = f.tellg();
    if (size < 0)
        return {};

    f.seekg(0, std::ios::beg);

    bytes data(static_cast<size_t>(size));
    if (size > 0)
        f.read(reinterpret_cast<char *>(data.data()), size);

    if (!f && size > 0)
        return {};

    return data;
}

inline bytes make_rsa_public_blob(const bytes& exponent_be, const bytes& modulus_be)
{
    BCRYPT_RSAKEY_BLOB hdr{};
    hdr.Magic = BCRYPT_RSAPUBLIC_MAGIC;
    hdr.BitLength = static_cast<ULONG>(modulus_be.size() * 8);
    hdr.cbPublicExp = static_cast<ULONG>(exponent_be.size());
    hdr.cbModulus = static_cast<ULONG>(modulus_be.size());
    hdr.cbPrime1 = 0;
    hdr.cbPrime2 = 0;

    bytes out(sizeof(hdr));
    std::memcpy(out.data(), &hdr, sizeof(hdr));

    out.insert(out.end(), exponent_be.begin(), exponent_be.end());
    out.insert(out.end(), modulus_be.begin(), modulus_be.end());

    return out;
}

struct DiskInfo
{
    std::wstring manufacturer;
    std::wstring model;
    std::wstring serial;
};

inline std::vector<DiskInfo> get_disks()
{
    std::vector<DiskInfo> out;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool need_uninit = (hr == S_OK || hr == S_FALSE);

    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
        return out;

    hr = CoInitializeSecurity(
        nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr
    );

    if (FAILED(hr) && hr != RPC_E_TOO_LATE)
    {
        if (need_uninit)
            CoUninitialize();
        return out;
    }

    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;
    IEnumWbemClassObject* pEnumerator = nullptr;

    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                     IID_IWbemLocator, reinterpret_cast<LPVOID *>(&pLoc));
    if (FAILED(hr))
        goto cleanup;

    hr = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        nullptr, nullptr, nullptr,
        0, nullptr, nullptr, &pSvc
    );
    if (FAILED(hr))
        goto cleanup;

    hr = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        nullptr,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE
    );
    if (FAILED(hr))
        goto cleanup;

    hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT Manufacturer, Model, SerialNumber FROM Win32_DiskDrive"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &pEnumerator
    );
    if (FAILED(hr))
        goto cleanup;

    while (true)
    {
        IWbemClassObject* pclsObj = nullptr;
        ULONG uReturn = 0;

        hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (FAILED(hr) || uReturn == 0)
            break;

        VARIANT vtProp;
        DiskInfo d{};

        VariantInit(&vtProp);

        if (SUCCEEDED(pclsObj->Get(L"Manufacturer", 0, &vtProp, nullptr, nullptr)) && vtProp.vt == VT_BSTR)
            d.manufacturer = vtProp.bstrVal;
        VariantClear(&vtProp);

        if (SUCCEEDED(pclsObj->Get(L"Model", 0, &vtProp, nullptr, nullptr)) && vtProp.vt == VT_BSTR)
            d.model = vtProp.bstrVal;
        VariantClear(&vtProp);

        if (SUCCEEDED(pclsObj->Get(L"SerialNumber", 0, &vtProp, nullptr, nullptr)) && vtProp.vt == VT_BSTR)
            d.serial = vtProp.bstrVal;
        VariantClear(&vtProp);

        out.push_back(d);

        pclsObj->Release();
    }

cleanup:
    if (pEnumerator)
        pEnumerator->Release();
    if (pSvc)
        pSvc->Release();
    if (pLoc)
        pLoc->Release();
    if (need_uninit)
        CoUninitialize();

    return out;
}

inline uint64_t get_ft_as_epoch()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);

    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart - 116444736000000000;
}

constexpr uint8_t rol8(const uint8_t x, uint32_t r)
{
    r &= 7;
    return static_cast<uint8_t>((x << r) | (x >> ((8 - r) & 7)));
}

constexpr uint32_t rol32(const uint32_t x, uint32_t r)
{
    r &= 31;
    return (x << r) | (x >> ((32 - r) & 31));
}