// SPDX-License-Identifier: GPL-3.0-only
/*
 * (C) Copyright 2024
 * Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 3 of
 * the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <sstream>
#include <iomanip>
#include <iostream>
#include <cstring>
#include <cstdint>

#ifdef USE_KERNEL_CRYPTO_API
#include <kcapi.h>
#endif

#include "sha256.h"

// SHA256 round constants
namespace {
const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
}  // namespace

// Utility: Right rotate
inline uint32_t rightRotate(uint32_t value, uint32_t count) {
    return (value >> count) | (value << (32 - count));
}

void sha256Transform(SHA256Ctx& context) {
    uint32_t w[64];
    for (size_t i = 0; i < 16; ++i) { // Use size_t for the loop index
        w[i] = (static_cast<uint32_t>(context.dataBlock[i * 4]) << 24) |
               (static_cast<uint32_t>(context.dataBlock[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(context.dataBlock[i * 4 + 2]) << 8) |
               (static_cast<uint32_t>(context.dataBlock[i * 4 + 3]));
    }
    for (size_t i = 16; i < 64; ++i) { // Use size_t here as well
        uint32_t s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = context.h[0];
    uint32_t b = context.h[1];
    uint32_t c = context.h[2];
    uint32_t d = context.h[3];
    uint32_t e = context.h[4];
    uint32_t f = context.h[5];
    uint32_t g = context.h[6];
    uint32_t h = context.h[7];

    for (size_t i = 0; i < 64; ++i) { // Again, size_t for consistency
        uint32_t S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + k[i] + w[i];
        uint32_t S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    context.h[0] += a;
    context.h[1] += b;
    context.h[2] += c;
    context.h[3] += d;
    context.h[4] += e;
    context.h[5] += f;
    context.h[6] += g;
    context.h[7] += h;
}

int sha256Init(SHA256Ctx& context) {
    if (!context.initialized) {
#ifdef USE_KERNEL_CRYPTO_API
        const char *hashname = "sha256";
        static bool warned = false;
        int ret;

        ret = kcapi_md_init(&context.handle, hashname, 0);
        if ((ret != 0) && !warned) {
            std::cerr << "Failed to init kernel crypto API: " << ret << std::endl;
            std::cerr << "Falling back to software hashing" << std::endl;
            warned = true;
        }
#endif
        context.initialized = true;
    }

    return 0;
}

int sha256Update(SHA256Ctx& context, const void *data, size_t length) {
    const uint8_t* input = static_cast<const uint8_t*>(data);
    int ret = -1;

    if (context.initialized) {
#ifdef USE_KERNEL_CRYPTO_API
        if (context.handle != nullptr) {
            if (kcapi_md_update(context.handle, input, length) == 0) {
                ret = 0;
            }
        } else
#endif
        {
            // Fill the 64-byte block in bulk. Copying byte by byte, as this
            // used to, dominates the cost of verifying a large image on any
            // target without the kernel crypto API.
            while (length > 0) {
                const size_t space = sizeof(context.dataBlock) - context.dataBlockIndex;
                const size_t take = (length < space) ? length : space;

                std::memcpy(&context.dataBlock[context.dataBlockIndex], input, take);
                context.dataBlockIndex += take;
                context.bitLength += static_cast<uint64_t>(take) * 8;
                input += take;
                length -= take;

                if (context.dataBlockIndex == sizeof(context.dataBlock)) {
                    sha256Transform(context);
                    context.dataBlockIndex = 0;
                }
            }
            ret = 0;
        }
    }

    return ret;
}

int sha256Update(SHA256Ctx& context, const std::string& data) {
    return sha256Update(context, data.data(), data.size());
}

std::string sha256Finalize(SHA256Ctx& context) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');

    if (context.initialized) {
#ifdef USE_KERNEL_CRYPTO_API
        if (context.handle != nullptr) {
            std::array<uint8_t, 64> buf;
            ssize_t ret = kcapi_md_final(context.handle, buf.data(), buf.size());
            kcapi_md_destroy(context.handle);
            context.handle = nullptr;

            if (ret < 0) {
                std::cerr << "Kernel crypto API failed to finalize the hash: " << ret << std::endl;
                return std::string();
            }

            for (ssize_t i = 0; i < ret; i++) {
                output << std::setw(2) << static_cast<uint32_t>(buf.data()[i]);
            }
        } else
#endif
        {
            context.dataBlock[context.dataBlockIndex++] = 0x80;

            if (context.dataBlockIndex > 56) {
                while (context.dataBlockIndex < 64) {
                    context.dataBlock[context.dataBlockIndex++] = 0x00;
                }
                sha256Transform(context);
                context.dataBlockIndex = 0;
            }

            while (context.dataBlockIndex < 56) {
                context.dataBlock[context.dataBlockIndex++] = 0x00;
            }

            uint64_t bitLengthBigEndian = __builtin_bswap64(context.bitLength);
            std::memcpy(&context.dataBlock[56], &bitLengthBigEndian, sizeof(bitLengthBigEndian));
            sha256Transform(context);

            for (uint32_t value : context.h) {
                output << std::setw(8) << value;
            }
        }
    }

    return output.str();
}
