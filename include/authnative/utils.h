//
// Created by wane on 26. 4. 13..
//

#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <fstream>

#include <Windows.h>

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
