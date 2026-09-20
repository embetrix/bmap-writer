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

#ifndef BMAP_H
#define BMAP_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct range_t {
    std::string checksum;
    size_t startBlock = 0;
    size_t endBlock = 0;
};

struct bmap_t {
    std::vector<range_t> ranges;
    std::string checksumType;
    size_t blockSize = 0;
    size_t blocksTotal = 0;
    size_t blocksMapped = 0;
    std::string bmapVersion;
    std::string bmapChecksum;
};

// Parse metadata, validate sizes/ranges, and verify the BMAP file checksum.
// Each operation returns EXIT_SUCCESS or EXIT_FAILURE and reports errors.
int parseBMap(const std::string& filename, bmap_t& bmapData);
int validateBmap(const bmap_t& bmap, uint64_t deviceSize);
int checkBmap(const std::string& filename, const std::string& checksum);

#endif // BMAP_H
