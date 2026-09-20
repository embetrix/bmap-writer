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

#ifndef BMAP_DEVICE_H
#define BMAP_DEVICE_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <sys/types.h>

enum mount_state_t {
    DEVICE_UNMOUNTED = 0,
    DEVICE_MOUNTED,
    DEVICE_SCAN_FAILED,
};

bool isPipe(int fd);
mount_state_t isDeviceMounted(const std::string& devicePath);
int openTargetDevice(const std::string& device);
// Returns zero for targets without a known fixed capacity (e.g. regular files).
uint64_t getDeviceSize(int fd);

// Complete the transfer or throw BmapError on failure.
void writeFully(int fd, const char* data, size_t length, off_t offset);
void readFully(int fd, char* data, size_t length, off_t offset);
void flushDevice(int fd);

#endif // BMAP_DEVICE_H
