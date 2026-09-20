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

#include "device.h"
#include "error.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

bool isPipe(int fd) {
    struct stat statbuf;
    bool pipe = false;

    if (::fstat(fd, &statbuf) != 0) {
        std::cerr << "Failed to stat fd for pipe detection: " << strerror(errno) << std::endl;
    } else if (S_ISFIFO(statbuf.st_mode)) {
        pipe = true;
    }

    return pipe;
}

static bool isPartitionOf(const std::string& source, const std::string& device)
{
    if (device.empty() || source.compare(0, device.size(), device) != 0) {
        return false;
    }
    std::string suffix = source.substr(device.size());
    if (suffix.empty()) {
        return false;
    }
    // Devices ending in a digit use "p" before the partition number:
    // /dev/mmcblk0p1, /dev/nvme0n1p1
    if (std::isdigit(static_cast<unsigned char>(device.back()))) {
        if (suffix.front() != 'p') {
            return false;
        }
        suffix.erase(0, 1);
    }
    // Other devices use the number directly:
    // /dev/sda1
    return !suffix.empty() &&
           std::all_of(suffix.begin(), suffix.end(),
                       [](unsigned char c) { return std::isdigit(c); });
}

// /proc/mounts always records the canonical /dev/... name, so the path the
// user gave has to be resolved before it can be compared. Without this,
// /dev/disk/by-uuid/... and /dev/./sda1 both slip past the check.
static std::string canonicalDevicePath(const std::string& device)
{
    char resolved[PATH_MAX];

    if (::realpath(device.c_str(), resolved) != nullptr) {
        return std::string(resolved);
    }

    // The target does not exist yet, so it cannot be mounted either.
    return device;
}

mount_state_t isDeviceMounted(const std::string& devicePath)
{
    const std::string device = canonicalDevicePath(devicePath);
    std::ifstream mounts("/proc/mounts");
    std::string line;

    if (!mounts.is_open()) {
        std::cerr << "Failed to open /proc/mounts: " << strerror(errno) << std::endl;
        return DEVICE_SCAN_FAILED;
    }

    while (std::getline(mounts, line)) {
        std::istringstream entry(line);
        std::string source;

        if (!(entry >> source)) {
            continue;
        }

        if (source == device || isPartitionOf(source, device)) {
            return DEVICE_MOUNTED;
        }
    }

    // The loop also ends on a read error which leaves the mount table
    // only partially scanned
    if (mounts.bad()) {
        std::cerr << "Failed to read /proc/mounts: " << strerror(errno) << std::endl;
        return DEVICE_SCAN_FAILED;
    }

    return DEVICE_UNMOUNTED;
}

// Opens the write target. For a block device O_EXCL makes the kernel refuse
// the open while the device is mounted or otherwise claimed which also closes
// the race between the /proc/mounts scan and this open. Only a path that does
// not exist yet is created, so a typo in a device name is now an error instead
// of a silently created regular file.
int openTargetDevice(const std::string& device) {
    struct stat statbuf;
    const bool exists = (::stat(device.c_str(), &statbuf) == 0);
    int flags = O_RDWR;

    if (!exists) {
        flags |= O_CREAT | O_EXCL;
    } else if (S_ISBLK(statbuf.st_mode)) {
        flags |= O_EXCL;
    }

    const int fd = ::open(device.c_str(), flags, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        std::cerr << "Unable to open target device " << device << ": " << strerror(errno) << std::endl;
        if (errno == EBUSY) {
            std::cerr << "The device is in use: it is mounted or claimed by another process." << std::endl;
        }
    }

    return fd;
}

// Capacity of the target in bytes, or 0 when it cannot be determined (a
// regular file which simply grows as needed).
uint64_t getDeviceSize(int fd) {
    struct stat statbuf;
    uint64_t size = 0;

    if (::fstat(fd, &statbuf) != 0) {
        return 0;
    }
    if (S_ISBLK(statbuf.st_mode) && (::ioctl(fd, BLKGETSIZE64, &size) != 0)) {
        return 0;
    }

    return size;
}

// pwrite and pread are both allowed to transfer fewer bytes than asked for.
// Treating that as success leaves a hole in the image; treating it as an error
// fails a perfectly valid transfer. Both have to loop.
void writeFully(int fd, const char *data, size_t length, off_t offset) {
    size_t done = 0;

    while (done < length) {
        const ssize_t written = ::pwrite(fd, data + done, length - done,
                                         offset + static_cast<off_t>(done));
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw BmapError(std::string("Write to device failed: ") + strerror(errno));
        }
        if (written == 0) {
            throw BmapError("Write to device made no progress");
        }
        done += static_cast<size_t>(written);
    }
}

void readFully(int fd, char *data, size_t length, off_t offset) {
    size_t done = 0;

    while (done < length) {
        const ssize_t got = ::pread(fd, data + done, length - done,
                                    offset + static_cast<off_t>(done));
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw BmapError(std::string("Failed to re-read from device: ") + strerror(errno));
        }
        if (got == 0) {
            throw BmapError("Unexpected end of device while verifying");
        }
        done += static_cast<size_t>(got);
    }
}

void flushDevice(int fd) {
    if (::fsync(fd) == 0) {
        return;
    }
    // Not every target supports flushing; that is not a write failure.
    if ((errno == EINVAL) || (errno == ENOTSUP)) {
        return;
    }
    throw BmapError(std::string("Failed to flush device: ") + strerror(errno));
}
