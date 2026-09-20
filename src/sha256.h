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

#ifndef SHA256_H
#define SHA256_H

#include <string>
#include <array>
#include <cstdint>
#include <cstddef>

#ifdef USE_KERNEL_CRYPTO_API
#include <kcapi.h>
#endif

// SHA256 context structure
struct SHA256Ctx {
    std::array<uint32_t, 8> h = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint64_t bitLength = 0;
    std::array<uint8_t, 64> dataBlock{};
    size_t dataBlockIndex = 0;
#ifdef USE_KERNEL_CRYPTO_API
    struct kcapi_handle *handle = nullptr;
#endif
    bool initialized = false;
};

// Public functions. All return 0 on success and -1 on failure.
int sha256Init(SHA256Ctx& context);
int sha256Update(SHA256Ctx& context, const void *data, size_t length);
int sha256Update(SHA256Ctx& context, const std::string& data);
// Returns the hex digest, or an empty string if the context is unusable.
std::string sha256Finalize(SHA256Ctx& context);

#endif // SHA256_H
