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

#include "image_writer.h"
#include "bmap.h"
#include "device.h"
#include "error.h"
#include "sha256.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <vector>

#include <archive.h>
#include <fcntl.h>
#include <sys/sysinfo.h>

static int getFreeMemory(size_t *memory, unsigned int divider) {
    struct sysinfo info;
    int ret;

    ret = sysinfo(&info);
    if (ret == 0) {
        // freeram counts mem_unit-sized units which is 1 on 64-bit Linux but
        // not on every 32-bit configuration.
        uint64_t bytes = static_cast<uint64_t>(info.freeram) * static_cast<uint64_t>(info.mem_unit);
        if (divider > 0) {
            bytes /= divider;
        }
        const uint64_t limit = static_cast<uint64_t>(std::numeric_limits<size_t>::max());
        *memory = static_cast<size_t>((bytes > limit) ? limit : bytes);
    }

    return ret;
}

// A handful of megabytes already saturates any storage device. The previous
// heuristic of "half of free RAM" bought no throughput, starved the rest of
// the system and turned an oversized range into an out-of-memory kill.
static const size_t MAX_BUFFER_SIZE = 8u * 1024u * 1024u;

static size_t chooseBufferSize(size_t blockSize) {
    size_t freeMemory = 0;
    size_t bufferSize = MAX_BUFFER_SIZE;

    if ((getFreeMemory(&freeMemory, 4) == 0) && (freeMemory < bufferSize)) {
        bufferSize = freeMemory;
    }
    if (bufferSize < blockSize) {
        bufferSize = blockSize;
    }

    return bufferSize;
}

class ArchiveGuard {
public:
    explicit ArchiveGuard(struct archive *a) : a_(a) {}
    ~ArchiveGuard() { if (a_ != nullptr) { archive_read_free(a_); } }
    ArchiveGuard(const ArchiveGuard&) = delete;
    ArchiveGuard& operator=(const ArchiveGuard&) = delete;
    struct archive *get() const { return a_; }
private:
    struct archive *a_;
};

// Reads the range back off the device and checks it against the checksum from
// the bmap. The page cache is dropped first, so this measures what actually
// reached the medium rather than what is still sitting in RAM.
static void verifyRange(int dev_fd, const range_t &range, off_t offset, size_t rangeSize,
                        std::vector<char> &buffer) {
    flushDevice(dev_fd);
#ifdef POSIX_FADV_DONTNEED
    (void)::posix_fadvise(dev_fd, offset, static_cast<off_t>(rangeSize), POSIX_FADV_DONTNEED);
#endif

    SHA256Ctx verifySha256Ctx = {};
    if (sha256Init(verifySha256Ctx) != 0) {
        throw BmapError("Failed to initialize hasher");
    }

    size_t readSize = 0;
    while (readSize < rangeSize) {
        size_t chunkSize = buffer.size();
        if (chunkSize > (rangeSize - readSize)) {
            chunkSize = rangeSize - readSize;
        }

        readFully(dev_fd, buffer.data(), chunkSize, offset + static_cast<off_t>(readSize));

        if (sha256Update(verifySha256Ctx, buffer.data(), chunkSize) != 0) {
            throw BmapError("Failed to hash the data read back from the device");
        }

        readSize += chunkSize;
    }

    const std::string computedChecksum = sha256Finalize(verifySha256Ctx);
    if (computedChecksum.compare(range.checksum) != 0) {
        std::stringstream err;
        err << "Read-back verification failed for range: " << range.startBlock << " - " << range.endBlock << std::endl;
        err << "Read Checksum: " << computedChecksum << std::endl;
        err << "Expected Checksum: " << range.checksum;
        throw BmapError(err.str());
    }
}

int BmapWriteImage(int fd, const bmap_t &bmap, int dev_fd, const std::string &device, bool noVerify) {
    auto start = std::chrono::high_resolution_clock::now();

    try {
        ArchiveGuard archiveGuard(archive_read_new());
        struct archive *a = archiveGuard.get();

        if (a == nullptr) {
            throw BmapError("Failed to allocate an archive reader");
        }

        /* Support all compression types */
        archive_read_support_filter_all(a);

        /* Support a single compressed file or tar archive */
        archive_read_support_format_raw(a);
        archive_read_support_format_tar(a);

        if (archive_read_open_fd(a, fd, READ_BLK_SIZE) != ARCHIVE_OK) {
            const char *aerr = archive_error_string(a);
            throw BmapError(std::string("Failed to open archive: ") +
                            ((aerr != nullptr) ? aerr : "unknown error"));
        }

        if (archive_format_name(a) != nullptr) {
            std::cout << "Detected format: " << archive_format_name(a) << std::endl;
        }

        /* Last filter is always the wrapper and would be printed as "none" */
        for (int i = 0; i < archive_filter_count(a) - 1; i++) {
            std::cout << "Detected compression: " << archive_filter_name(a, i) << std::endl;
        }

        struct archive_entry *ae;
        if (archive_read_next_header(a, &ae) != ARCHIVE_OK) {
            const char *aerr = archive_error_string(a);
            throw BmapError(std::string("Failed to read archive header: ") +
                            ((aerr != nullptr) ? aerr : "unknown error"));
        }

        // One allocation for the whole run, rather than one per chunk.
        std::vector<char> buffer(chooseBufferSize(bmap.blockSize));

        size_t decHead = 0;
        size_t totalWrittenSize = 0;

        for (const auto &range : bmap.ranges) {
            // validateBmap() has already proven that none of this can overflow.
            const size_t outStart = range.startBlock * bmap.blockSize;
            const size_t outEnd = (range.endBlock + 1) * bmap.blockSize;
            const size_t rangeSize = outEnd - outStart;
            const off_t writeOffset = static_cast<off_t>(outStart);
            size_t writtenSize = 0;
            bool endOfFile = false;

            while ((writtenSize < rangeSize) && !endOfFile) {
                size_t outBytes = 0;

                size_t chunkLimit = buffer.size();
                if (chunkLimit > (rangeSize - writtenSize)) {
                    chunkLimit = (rangeSize - writtenSize);
                }

                while (outBytes < chunkLimit) {
                    const ssize_t readData = archive_read_data(a, buffer.data() + outBytes,
                                                               chunkLimit - outBytes);

                    // A negative return is a decompression failure and must not
                    // be mistaken for a clean end of stream.
                    if (readData < 0) {
                        const char *aerr = archive_error_string(a);
                        throw BmapError(std::string("Failed to read image data: ") +
                                        ((aerr != nullptr) ? aerr : "unknown error"));
                    }
                    if (readData == 0) {
                        endOfFile = true;
                        break;
                    }

                    const size_t chunkSize = static_cast<size_t>(readData);

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

                writeFully(dev_fd, buffer.data(), outBytes,
                           writeOffset + static_cast<off_t>(writtenSize));

                writtenSize += outBytes;
                totalWrittenSize += outBytes;
            }

            // The bmap states exactly how many bytes this range needs. Anything
            // short means the image was truncated or the stream ended early,
            // which is an error even when checksum verification is disabled.
            if (writtenSize != rangeSize) {
                throw BmapError("Image ended before the block map did: range " +
                                std::to_string(range.startBlock) + "-" + std::to_string(range.endBlock) +
                                " needs " + std::to_string(rangeSize) + " bytes but only " +
                                std::to_string(writtenSize) + " were available");
            }

            if (!noVerify) {
                verifyRange(dev_fd, range, writeOffset, rangeSize, buffer);
            }
        }

        // Every byte the block map asked for has been written, but the tail
        // of the stream has not been read yet and that is where a
        // compressor keeps its checksum and tar keeps its trailer. A zero
        // from archive_read_data only ends the current entry, so drain all
        // the way to ARCHIVE_EOF. This is what turns a corrupt archive into
        // an error instead of a silent success, and with -n it is the only
        // integrity check left.
        int drain = ARCHIVE_OK;
        while (drain == ARCHIVE_OK) {
            ssize_t readData;
            while ((readData = archive_read_data(a, buffer.data(), buffer.size())) > 0) {
                // Past the end of the block map: read for validation, discard.
            }
            if (readData < 0) {
                const char *aerr = archive_error_string(a);
                throw BmapError(std::string("Image stream is corrupt: ") +
                                ((aerr != nullptr) ? aerr : "unknown error"));
            }

            drain = archive_read_next_header(a, &ae);
            if (drain != ARCHIVE_OK && drain != ARCHIVE_EOF) {
                const char *aerr = archive_error_string(a);
                throw BmapError(std::string("Image stream is corrupt: ") +
                                ((aerr != nullptr) ? aerr : "unknown error"));
            }
        }

        // Without O_SYNC on every write, this is what makes the data durable.
        flushDevice(dev_fd);

        if (noVerify) {
            std::cout << "Checksum verification skipped" << std::endl;
        }

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end - start;
        std::cout << "Finished writing image to device: " << device
                  << " time: " << std::fixed << std::setprecision(2) << elapsed.count() << "s";
        if (elapsed.count() > 0.0) {
            const double speed = static_cast<double>(totalWrittenSize) / elapsed.count() / (1024 * 1024);
            std::cout << " speed: " << std::fixed << std::setprecision(2) << speed << " MB/s";
        }
        std::cout << std::endl;
    }
    catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
