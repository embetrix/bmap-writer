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

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <iomanip>
#include <string>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cerrno>

#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>

#include <archive.h>
#include <tinyxml2.h>

#include "sha256.h"

struct range_t {
    std::string checksum;
    size_t startBlock;
    size_t endBlock;
};

struct bmap_t {
    std::vector<range_t> ranges;
    std::string checksumType;
    size_t blockSize;
    size_t blocksTotal;
    size_t blocksMapped;
    std::string bmapVersion;
    std::string bmapChecksum;
};

int parseBMap(const std::string &filename, bmap_t& bmapData) {
    try {
        tinyxml2::XMLDocument doc;
        tinyxml2::XMLError err;

        err = doc.LoadFile(filename.c_str());
        if (err != tinyxml2::XML_SUCCESS) {
            throw std::string("Failed to load BMAP file");
        }

        tinyxml2::XMLElement * p_root = doc.RootElement();

        // Check if the provided file is a valid BMAP
        if (strcmp(reinterpret_cast<const char *>(p_root->Name()), "bmap") != 0) {
            throw std::string("BMAP file is invalid");
        }

        // Store BMAP version
        bmapData.bmapVersion = p_root->Attribute("version");

        // Parse image information
        tinyxml2::XMLElement * p_data;

        p_data = p_root->FirstChildElement("BlocksCount");
        if (p_data == nullptr) {
            throw std::string("BMAP: BlocksCount not found");
        } else {
            bmapData.blocksTotal = static_cast<size_t>(std::stoul(p_data->GetText()));
        }

        p_data = p_root->FirstChildElement("MappedBlocksCount");
        if (p_data == nullptr) {
            throw std::string("BMAP: MappedBlocksCount not found");
        } else {
            bmapData.blocksMapped = static_cast<size_t>(std::stoul(p_data->GetText()));
        }

        p_data = p_root->FirstChildElement("ChecksumType");
        if (p_data == nullptr) {
            throw std::string("BMAP: ChecksumType not found");
        } else {
            for (const auto ch: std::string(p_data->GetText())) {
                if (!std::isspace(ch)) {
                    bmapData.checksumType.push_back(static_cast<char>(std::tolower(ch)));
                }
            }
        }

        p_data = p_root->FirstChildElement("BmapFileChecksum");
        if (p_data == nullptr) {
            throw std::string("BMAP: BmapFileChecksum not found");
        } else {
            for (const auto ch: std::string(p_data->GetText())) {
                if (!std::isspace(ch)) {
                    bmapData.bmapChecksum.push_back(static_cast<char>(ch));
                }
            }
        }

        p_data = p_root->FirstChildElement("BlockSize");
        if (p_data == nullptr) {
            throw std::string("BMAP: BlockSize not found");
        } else {
            bmapData.blockSize = static_cast<size_t>(std::stoul(p_data->GetText()));
        }

        p_data = p_root->FirstChildElement("BlockMap");
        if (p_data == nullptr) {
            throw std::string("BMAP: BlockMap not found");
        } else {
            tinyxml2::XMLElement * p_range = p_data->FirstChildElement("Range");
            while (p_range != nullptr) {
                range_t r;

                const char *val = p_range->GetText();
                if (val == nullptr) {
                    throw std::string("BMAP: found an empty range");
                }

                const char *chksum = p_range->Attribute("chksum");
                if (chksum == nullptr) {
                    throw std::string("BMAP: following range has no checksum: ") + std::string(val);
                }

                int parseResult = std::sscanf(val, "%zu-%zu", &r.startBlock, &r.endBlock);
                switch (parseResult) {
                case 2:
                    // Multiple blocks range, nothing to do
                    break;
                case 1:
                    // Handle single block range
                    r.endBlock = r.startBlock;
                    break;
                default:
                    throw std::string("BMAP: invalid range: ") + std::string(val);
                }

                r.checksum = std::string(chksum);

                //std::cout << "Parsed Range: checksum=" << r.checksum << ", range=" << r.startBlock << "-" << r.endBlock << std::endl;

                bmapData.ranges.push_back(r);

                p_range = p_range->NextSiblingElement("Range");
            }
        }
    } catch (const std::string& err) {
        std::cerr << err << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

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

bool isDeviceMounted(const std::string &device) {
    std::ifstream mounts("/proc/mounts");
    std::string line;
    while (std::getline(mounts, line)) {
        if (line.find(device) != std::string::npos) {
            return true;
        }
    }
    return false;
}

int getFreeMemory(size_t *memory, unsigned int divider = 1) {
    struct sysinfo info;
    int ret;

    ret = sysinfo(&info);
    if (ret == 0) {
        *memory = info.freeram;
        if (divider > 0) {
            *memory /= divider;
        }
    }

    return ret;
}

int BmapWriteImage(int fd, const bmap_t &bmap, const std::string &device, bool noVerify) {
    struct archive *a = nullptr;
    int dev_fd = -1;
    int ret = EXIT_SUCCESS;
    auto start = std::chrono::high_resolution_clock::now();
    try {
        size_t decHead = 0;

        dev_fd = open(device.c_str(), O_RDWR | O_CREAT | O_SYNC, S_IRUSR | S_IWUSR);
        if (dev_fd < 0) {
            throw std::string("Unable to open or create target device");
        }

        a = archive_read_new();

        /* Support all compression types */
        archive_read_support_filter_all(a);

        /* Support a single compressed file or tar archive */
        archive_read_support_format_raw(a);
        archive_read_support_format_tar(a);

        int r = archive_read_open_fd(a, fd, READ_BLK_SIZE);
        if (r != ARCHIVE_OK) {
            throw std::string("Failed to open archive: ") + std::string(archive_error_string(a));
        } else {
            if (archive_format_name(a) != nullptr) {
                std::cout << "Detected format: " << std::string(archive_format_name(a)) << std::endl;
            }

            /* Last filter is always the wrapper and would be printed as "none" */
            for (int i = 0; i < archive_filter_count(a) - 1; i++) {
                std::cout << "Detected compression: " << std::string(archive_filter_name(a, i)) << std::endl;
            }
        }

        struct archive_entry *ae;
        r = archive_read_next_header(a, &ae);
        if (r != ARCHIVE_OK) {
            const char * aerr = archive_error_string(a);
            throw std::string("Failed to read archive header: ") + ((aerr != nullptr) ? std::string(aerr) : "unknown error");
        }

        size_t totalWrittenSize = 0;
        for (const auto &range : bmap.ranges) {
            //std::cout << "Processing Range: startBlock=" << range.startBlock << ", endBlock=" << range.endBlock << std::endl;
            const size_t outStart = range.startBlock * bmap.blockSize;
            const size_t outEnd = ((range.endBlock + 1) * bmap.blockSize);
            const size_t rangeSize = (range.endBlock - range.startBlock + 1) * bmap.blockSize;
            const off_t writeOffset = static_cast<off_t>(range.startBlock * bmap.blockSize);
            size_t maxBufferSize = 0;
            size_t writtenSize = 0;
            bool endOfFile = false;

            if (getFreeMemory(&maxBufferSize, 2) < 0) {
                throw std::string("Failed to get free memory");
            } else if (maxBufferSize < bmap.blockSize) {
                maxBufferSize = bmap.blockSize;
            }

            while ((writtenSize < rangeSize) && !endOfFile) {
                size_t outBytes = 0;

                size_t bufferSize = maxBufferSize;
                if (bufferSize > (rangeSize - writtenSize)) {
                    bufferSize = (rangeSize - writtenSize);
                }

                std::vector<char> buffer(bufferSize);

                while (outBytes < bufferSize) {
                    ssize_t readData = archive_read_data(a, buffer.data() + outBytes, bufferSize - outBytes);

                    // If no more data is available in the input buffer and the input file has been
                    // read completely, stop this decompression loop
                    if (readData <= 0) {
                        endOfFile = true;
                        break;
                    }

                    size_t chunkSize = static_cast<size_t>(readData);

                    if (decHead >= outStart && (decHead + chunkSize) <= outEnd) {
                        // Case 1: all decoded data can be used
                        outBytes += chunkSize;
                    } else if (decHead < outStart && (decHead + chunkSize) <= outStart) {
                        // Case 2: all decoded data shall be discarded
                    } else if (decHead < outStart && (decHead + chunkSize) > outStart) {
                        // Case 3: only the last portion of the decoded data can be used
                        std::move(buffer.begin() + static_cast<long int>(outStart - decHead),
                                  buffer.begin() + static_cast<long int>(chunkSize),
                                  buffer.begin());
                        size_t validData = chunkSize - (outStart - decHead);
                        outBytes += validData;
                    }

                    // Advance the head of the decompressed data
                    decHead += chunkSize;
                }

                if (pwrite(dev_fd, buffer.data(), outBytes, writeOffset + static_cast<off_t>(writtenSize)) < 0) {
                    throw std::string("Write to device failed");
                }

                writtenSize += outBytes;
                totalWrittenSize += outBytes;
            }

            if (!noVerify) {
                // Read back written data and compute checksum on it.
                size_t readSize = 0;
                SHA256Ctx verifySha256Ctx = {};

                while (readSize < writtenSize) {
                    size_t bufferSize = (maxBufferSize > 0) ? maxBufferSize : writtenSize;
                    if (bufferSize > (writtenSize - readSize)) {
                        bufferSize = (writtenSize - readSize);
                    }

                    std::vector<char> buffer(bufferSize);

                    ssize_t readData = pread(dev_fd, buffer.data(), buffer.size(), writeOffset + static_cast<off_t>(readSize));
                    if (readData != buffer.size()) {
                        throw std::string("Failed to re-read from device: ") + std::to_string(readData);
                    }

                    sha256Update(verifySha256Ctx, std::string(buffer.data(), buffer.size()));

                    readSize += static_cast<size_t>(readData);
                }

                std::string computedChecksum = sha256Finalize(verifySha256Ctx);

                if (computedChecksum.compare(range.checksum) != 0) {
                    std::stringstream err;
                    err << "Read-back verification failed for range: " << range.startBlock << " - " << range.endBlock << std::endl;
                    err << "Read Checksum: " << computedChecksum << std::endl;
                    err << "Expected Checksum: " << range.checksum;
                    throw std::string(err.str());
                }
            }
        }
        if (noVerify) {
            std::cout << "Checksum verification skipped" << std::endl;
        }

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end - start;
        double speed = static_cast<double>(totalWrittenSize) / elapsed.count() / (1024 * 1024); // Speed in MB/s
        std::cout << "Finished writing image to device: " << device
              << " time: " << std::fixed << std::setprecision(2)
              << elapsed.count() << "s speed: " << std::fixed << std::setprecision(2)
              << speed << " MB/s" << std::endl;
    }
    catch (const std::string& err) {
        std::cerr << err << std::endl;
        ret =  EXIT_FAILURE;
    }

    if (dev_fd >= 0) {
        close(dev_fd);
    }

    if (a != nullptr) {
        archive_read_free(a);
    }

    return ret;
}

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

    if ((argc - optind) < 2 || (argc - optind) > 4) {
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

    if (isDeviceMounted(device)) {
        std::cerr << "Error device: " << device << " is mounted. Please unmount it before proceeding." << std::endl;
        return EXIT_FAILURE;
    }

    bmap_t bmap;
    int ret = parseBMap(bmapFile, bmap);
    if (ret != 0) {
        std::cerr << "Failed to parse BMAP file: " << bmapFile << std::endl;
        return EXIT_FAILURE;
    }

    if (bmap.checksumType != "sha256") {
        std::cerr << "Unsupported checksum type: " << bmap.checksumType << std::endl;
        return EXIT_FAILURE;
    }

    if (image_fd < 0) {
        image_fd = ::open(imageFile.c_str(), O_RDONLY);
        if (image_fd < 0) {
            std::cerr << "Failed to open image file: " << imageFile << std::endl;
            return EXIT_FAILURE;
        }
    }

    std::cout << "BMAP format version: " << bmap.bmapVersion << std::endl;
    std::cout << "Image size: " << (bmap.blocksTotal * bmap.blockSize) << " bytes" << std::endl;
    std::cout << "Block size: " << bmap.blockSize << " bytes" << std::endl;
    std::cout << "Mapped blocks: " << bmap.blocksMapped << " out of " << bmap.blocksTotal
              << " (" << std::fixed << std::setprecision(1)
              << (100.0 * static_cast<float>(bmap.blocksMapped) / static_cast<float>(bmap.blocksTotal))
              << "%)" << std::endl;

    ret = BmapWriteImage(image_fd, bmap, device, noVerify);
    if (ret != 0) {
        std::cerr << "Failed to write image to device: " << device << std::endl;
    }

    if (image_fd >= 0) {
        close(image_fd);
    }

    return ret;
}
