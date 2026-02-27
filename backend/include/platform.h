#ifndef PLATFORM_H
#define PLATFORM_H

#include <cstdint>
#include <type_traits>

namespace PortableNet {

constexpr uint16_t swapBytes16(uint16_t value) {
    return static_cast<uint16_t>((value << 8) | (value >> 8));
}

constexpr uint32_t swapBytes32(uint32_t value) {
    return ((value & 0x000000FFu) << 24) |
           ((value & 0x0000FF00u) << 8)  |
           ((value & 0x00FF0000u) >> 8)  |
           ((value & 0xFF000000u) >> 24);
}

constexpr uint64_t swapBytes64(uint64_t value) {
    return ((value & 0x00000000000000FFull) << 56) |
           ((value & 0x000000000000FF00ull) << 40) |
           ((value & 0x0000000000FF0000ull) << 24) |
           ((value & 0x00000000FF000000ull) << 8)  |
           ((value & 0x000000FF00000000ull) >> 8)  |
           ((value & 0x0000FF0000000000ull) >> 24) |
           ((value & 0x00FF000000000000ull) >> 40) |
           ((value & 0xFF00000000000000ull) >> 56);
}

constexpr bool isLittleEndian() {
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
    return __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__;
#else
    return static_cast<bool>(
        *reinterpret_cast<const uint8_t*>(
            static_cast<const void*>(&"\x01")));
#endif
}

constexpr uint16_t netToHost16(uint16_t value) {
    return isLittleEndian() ? swapBytes16(value) : value;
}

constexpr uint32_t netToHost32(uint32_t value) {
    return isLittleEndian() ? swapBytes32(value) : value;
}

constexpr uint64_t netToHost64(uint64_t value) {
    return isLittleEndian() ? swapBytes64(value) : value;
}

constexpr uint16_t hostToNet16(uint16_t value) {
    return netToHost16(value);
}

constexpr uint32_t hostToNet32(uint32_t value) {
    return netToHost32(value);
}

constexpr uint64_t hostToNet64(uint64_t value) {
    return netToHost64(value);
}

}

#endif
