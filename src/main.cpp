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

#include "bmap.h"
#include "device.h"
#include "fd_guard.h"
#include "image_writer.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

#include <fcntl.h>
#include <getopt.h>

static void printUsage(const char *progname) {
    std::cout << "Usage: " << progname << " "
              << "[-hvn] <image-file> [<bmap-file>] <target-device>" << std::endl;
    std::cout << std::endl;
    std::cout << "-n : Skip checksum verification" << std::endl;
    std::cout << "-v : Show version" << std::endl;
    std::cout << "-h : Show this help and exit" << std::endl;
    std::cout << std::endl;
    std::cout << "To use stdin as source of the image file, <image-file> shall be equal\n"
              << "to - and <bmap-file> shall be present." << std::endl;
}

int main(int argc, char *argv[]) {
    bool noVerify = false;
    int opt;

    while ((opt = getopt(argc, argv, "hnv")) != -1) {
        switch (opt) {
            case 'n':
                noVerify = true;
                break;
            case 'h':
                printUsage(argv[0]);
                return EXIT_SUCCESS;
            case 'v':
                if (std::strlen(GIT_VERSION) > 0) {
                    std::cout << "Version: " << GIT_VERSION  << std::endl;
                }
                return EXIT_SUCCESS;
            default:
                std::cerr << "Unknown option -" << static_cast<char>(opt) << std::endl;
                printUsage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if ((argc - optind) < 2 || (argc - optind) > 3) {
        std::cerr << "Wrong number of args" << std::endl;
        printUsage(argv[0]);
        return EXIT_FAILURE;
    }

    std::string imageFile = argv[optind];
    std::string bmapFile;
    std::string device;
    int image_fd = -1;

    if ((argc - optind) == 3) {
        bmapFile = argv[optind + 1];
        device = argv[optind + 2];

        if (imageFile.compare("-") == 0) {
            image_fd = ::fileno(stdin);
            if (!isPipe(image_fd)) {
                std::cerr << "Error: stdin specified as input but it's not a pipe." << std::endl;
                return EXIT_FAILURE;
            }
        }
    } else {
        size_t pos = imageFile.find_last_of('.');
        if (pos != std::string::npos) {
            bmapFile = imageFile.substr(0, pos) + ".bmap";
        } else {
            bmapFile = imageFile + ".bmap";
        }
        std::cout << "Using default bmap file: " << bmapFile << std::endl;
        std::ifstream fileCheck(bmapFile);
        if (!fileCheck) {
            std::cerr << "Error: bmap file not provided and default bmap file " << bmapFile << " does not exist." << std::endl;
            return EXIT_FAILURE;
        }
        device = argv[optind + 1];
    }

    if (std::strlen(GIT_VERSION) > 0) {
        std::cout << "Starting bmap-writer (" << GIT_VERSION << ")..." << std::endl;
    } else {
        std::cout << "Starting bmap-writer..." << std::endl;
    }

    mount_state_t mountState = isDeviceMounted(device);
    if (mountState == DEVICE_MOUNTED) {
        std::cerr << "Error device: " << device << " is mounted. Please unmount it before proceeding." << std::endl;
        return EXIT_FAILURE;
    } else if (mountState == DEVICE_SCAN_FAILED) {
        std::cerr << "Error: cannot determine whether device: " << device << " is mounted, refusing to write." << std::endl;
        return EXIT_FAILURE;
    }

    bmap_t bmap;
    if (parseBMap(bmapFile, bmap) != EXIT_SUCCESS) {
        std::cerr << "Failed to parse BMAP file: " << bmapFile << std::endl;
        return EXIT_FAILURE;
    }

    if (bmap.checksumType != "sha256") {
        std::cerr << "Unsupported checksum type: " << bmap.checksumType << std::endl;
        return EXIT_FAILURE;
    }

    // Everything below this point trusts values from the bmap as sizes and
    // offsets, so the file's own checksum is confirmed first.
    if (checkBmap(bmapFile, bmap.bmapChecksum) != EXIT_SUCCESS) {
        std::cerr << "BMAP file checksum failed" << std::endl;
        return EXIT_FAILURE;
    }

    // Opening the device before validation gives validateBmap() the capacity
    // to check the image against and O_EXCL rejects a mounted block device
    // even if the /proc/mounts scan above missed it.
    FdGuard devGuard(openTargetDevice(device));
    if (devGuard.get() < 0) {
        return EXIT_FAILURE;
    }

    if (validateBmap(bmap, getDeviceSize(devGuard.get())) != EXIT_SUCCESS) {
        std::cerr << "BMAP file failed validation: " << bmapFile << std::endl;
        return EXIT_FAILURE;
    }

    if (image_fd < 0) {
        image_fd = ::open(imageFile.c_str(), O_RDONLY);
        if (image_fd < 0) {
            std::cerr << "Failed to open image file: " << imageFile << ": " << strerror(errno) << std::endl;
            return EXIT_FAILURE;
        }
    }
    FdGuard imageGuard(image_fd);

    std::cout << "BMAP format version: " << bmap.bmapVersion << std::endl;
    std::cout << "Image size: " << (bmap.blocksTotal * bmap.blockSize) << " bytes" << std::endl;
    std::cout << "Block size: " << bmap.blockSize << " bytes" << std::endl;
    std::cout << "Mapped blocks: " << bmap.blocksMapped << " out of " << bmap.blocksTotal
              << " (" << std::fixed << std::setprecision(1)
              << (100.0 * static_cast<double>(bmap.blocksMapped) / static_cast<double>(bmap.blocksTotal))
              << "%)" << std::endl;

    int ret = BmapWriteImage(image_fd, bmap, devGuard.get(), device, noVerify);
    if (ret != EXIT_SUCCESS) {
        std::cerr << "Failed to write image to device: " << device << std::endl;
    }

    return ret;
}
