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
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <cstdint>
#include <climits>
#include <limits>
#include <stdexcept>

#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include <archive.h>
#include <tinyxml2.h>

#include "sha256.h"

// All recoverable failures are reported by throwing this type. Using a
// dedicated exception (rather than std::string) keeps the catch handlers
// compatible with the exceptions thrown by the standard library itself,
// e.g. std::invalid_argument from std::stoull or std::bad_alloc.
struct BmapError : public std::runtime_error {
    explicit BmapError(const std::string& what) : std::runtime_error(what) {}
};

enum mount_state_t {
    DEVICE_UNMOUNTED = 0,
    DEVICE_MOUNTED,
    DEVICE_SCAN_FAILED,
};

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

// A bmap block size is the source filesystem's block size, i.e. a few
// kilobytes. Anything beyond this is nonsense and since the read buffer is
// sized to hold at least one block it would turn straight into a wild
// allocation.
static const size_t MAX_BLOCK_SIZE = 16u * 1024u * 1024u;

static std::string trimWhitespace(const std::string& text) {
    const char *ws = " \t\r\n\f\v";
    const size_t first = text.find_first_not_of(ws);
    if (first == std::string::npos) {
        return std::string();
    }
    return text.substr(first, text.find_last_not_of(ws) - first + 1);
}

// Strict unsigned parser. Rejects the empty string, a leading sign (scanf's
// "%zu" happily wraps "-1" to SIZE_MAX), trailing garbage and values that do
// not fit in a size_t. Throws std::logic_error subclasses on failure.
static size_t parseUnsigned(const std::string& text) {
    if (text.empty() || std::isdigit(static_cast<unsigned char>(text[0])) == 0) {
        throw std::invalid_argument("not an unsigned number");
    }
    size_t consumed = 0;
    const unsigned long long value = std::stoull(text, &consumed);
    if (consumed != text.size()) {
        throw std::invalid_argument("trailing garbage");
    }
    // size_t is narrower than unsigned long long on 32-bit targets.
    if (value > static_cast<unsigned long long>(std::numeric_limits<size_t>::max())) {
        throw std::out_of_range("does not fit in size_t");
    }
    return static_cast<size_t>(value);
}

// Text of a mandatory child element. tinyxml2 returns nullptr both for a
// missing element and for an empty one such as <BlocksCount></BlocksCount>;
// neither may ever reach a std::string constructor.
static std::string requireChildText(const tinyxml2::XMLElement *root, const char *tag) {
    const tinyxml2::XMLElement *element = root->FirstChildElement(tag);
    if (element == nullptr) {
        throw BmapError(std::string("BMAP: ") + tag + " not found");
    }
    const char *text = element->GetText();
    if (text == nullptr) {
        throw BmapError(std::string("BMAP: ") + tag + " is empty");
    }
    const std::string trimmed = trimWhitespace(text);
    if (trimmed.empty()) {
        throw BmapError(std::string("BMAP: ") + tag + " is empty");
    }
    return trimmed;
}

static size_t requireChildUnsigned(const tinyxml2::XMLElement *root, const char *tag) {
    const std::string text = requireChildText(root, tag);
    try {
        return parseUnsigned(text);
    } catch (const std::logic_error&) {
        throw BmapError(std::string("BMAP: ") + tag + " is not a valid number: " + text);
    }
}

// Accepts "<start>-<end>" as well as the single-block form "<block>".
static void parseRangeText(const std::string& raw, range_t& range) {
    const std::string text = trimWhitespace(raw);
    const size_t dash = text.find('-');
    try {
        range.startBlock = parseUnsigned(dash == std::string::npos ? text : text.substr(0, dash));
        range.endBlock = (dash == std::string::npos) ? range.startBlock
                                                     : parseUnsigned(text.substr(dash + 1));
    } catch (const std::logic_error&) {
        throw BmapError("BMAP: invalid range: " + text);
    }
}

int parseBMap(const std::string &filename, bmap_t& bmapData) {
    try {
        tinyxml2::XMLDocument doc;

        if (doc.LoadFile(filename.c_str()) != tinyxml2::XML_SUCCESS) {
            throw BmapError(std::string("Failed to load BMAP file: ") + doc.ErrorStr());
        }

        const tinyxml2::XMLElement *p_root = doc.RootElement();

        // A document holding only a comment parses successfully but has no
        // root element at all.
        if (p_root == nullptr) {
            throw BmapError("BMAP file has no root element");
        }

        // Check if the provided file is a valid BMAP
        if (strcmp(p_root->Name(), "bmap") != 0) {
            throw BmapError("BMAP file is invalid");
        }

        // Store BMAP version. The attribute is optional in practice, so a
        // missing one is reported rather than dereferenced.
        const char *version = p_root->Attribute("version");
        bmapData.bmapVersion = (version != nullptr) ? trimWhitespace(version) : "unknown";

        // Parse image information
        bmapData.blocksTotal = requireChildUnsigned(p_root, "BlocksCount");
        bmapData.blocksMapped = requireChildUnsigned(p_root, "MappedBlocksCount");
        bmapData.blockSize = requireChildUnsigned(p_root, "BlockSize");

        for (const auto ch: requireChildText(p_root, "ChecksumType")) {
            if (!std::isspace(static_cast<unsigned char>(ch))) {
                bmapData.checksumType.push_back(static_cast<char>(std::tolower(ch)));
            }
        }

        for (const auto ch: requireChildText(p_root, "BmapFileChecksum")) {
            if (!std::isspace(static_cast<unsigned char>(ch))) {
                bmapData.bmapChecksum.push_back(ch);
            }
        }

        const tinyxml2::XMLElement *p_data = p_root->FirstChildElement("BlockMap");
        if (p_data == nullptr) {
            throw BmapError("BMAP: BlockMap not found");
        }

        const tinyxml2::XMLElement *p_range = p_data->FirstChildElement("Range");
        while (p_range != nullptr) {
            range_t r;

            const char *val = p_range->GetText();
            if (val == nullptr) {
                throw BmapError("BMAP: found an empty range");
            }

            const char *chksum = p_range->Attribute("chksum");
            if (chksum == nullptr) {
                throw BmapError(std::string("BMAP: following range has no checksum: ") + val);
            }

            parseRangeText(val, r);
            r.checksum = trimWhitespace(chksum);

            bmapData.ranges.push_back(r);

            p_range = p_range->NextSiblingElement("Range");
        }
    } catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

// Sanity-checks every value that is later used as a size or an offset. The
// bmap file is attacker-controlled input in the download-and-flash workflow,
// so unsigned wrap-around here would turn into writes at arbitrary offsets.
int validateBmap(const bmap_t& bmap, uint64_t deviceSize) {
    try {
        if (bmap.blockSize == 0) {
            throw BmapError("BMAP: BlockSize must not be zero");
        }
        if (bmap.blockSize > MAX_BLOCK_SIZE) {
            throw BmapError("BMAP: BlockSize " + std::to_string(bmap.blockSize) +
                            " is implausibly large (limit is " + std::to_string(MAX_BLOCK_SIZE) + ")");
        }
        if (bmap.blocksTotal == 0) {
            throw BmapError("BMAP: BlocksCount must not be zero");
        }
        if (bmap.blocksMapped > bmap.blocksTotal) {
            throw BmapError("BMAP: MappedBlocksCount exceeds BlocksCount");
        }
        if (bmap.bmapChecksum.size() != 64 ||
            bmap.bmapChecksum.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
            throw BmapError("BMAP: BmapFileChecksum is not a SHA-256 hex digest");
        }

        const size_t maxBlock = std::numeric_limits<size_t>::max() / bmap.blockSize;

        // Guard the image size itself, not just the individual ranges: an
        // unbounded BlocksCount would wrap the product below and slip past
        // the device capacity check.
        if (bmap.blocksTotal > maxBlock) {
            throw BmapError("BMAP: BlocksCount " + std::to_string(bmap.blocksTotal) +
                            " overflows the address space at this block size");
        }

        bool first = true;
        size_t previousEnd = 0;

        for (const auto &range : bmap.ranges) {
            const std::string where = "BMAP: range " + std::to_string(range.startBlock) + "-" +
                                      std::to_string(range.endBlock) + " ";
            if (range.endBlock < range.startBlock) {
                throw BmapError(where + "ends before it starts");
            }
            if (range.endBlock >= bmap.blocksTotal) {
                throw BmapError(where + "extends past the end of the image");
            }
            // (endBlock + 1) * blockSize must not wrap around.
            if (range.endBlock + 1 > maxBlock) {
                throw BmapError(where + "overflows the address space");
            }
            // The decompression window walks the image forwards exactly once,
            // so overlapping or unsorted ranges would silently drop data.
            if (!first && range.startBlock <= previousEnd) {
                throw BmapError(where + "overlaps or precedes the previous range");
            }
            if (range.checksum.size() != 64 ||
                range.checksum.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
                throw BmapError(where + "has no valid SHA-256 checksum");
            }
            previousEnd = range.endBlock;
            first = false;
        }

        const uint64_t imageSize = static_cast<uint64_t>(bmap.blocksTotal) *
                                   static_cast<uint64_t>(bmap.blockSize);
        if (deviceSize > 0 && imageSize > deviceSize) {
            throw BmapError("Image needs " + std::to_string(imageSize) +
                            " bytes but the target device only holds " +
                            std::to_string(deviceSize) + " bytes");
        }
    } catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int checkBmap(const std::string &filename, const std::string& checksum) {
    try {
        std::ifstream file(filename);
        std::string line;

        if (!file.is_open()) {
            throw BmapError("Failed to open BMAP file");
        } else {
            SHA256Ctx sha256Ctx = {};

            if (sha256Init(sha256Ctx) != 0) {
                throw BmapError("Failed to initialize hasher");
            }

            while (std::getline(file, line)) {
                std::size_t found = line.find(checksum);
                // The actual checksum of the BMAP file shall be replaced with a set of '0'
                if (found != std::string::npos) {
                    line = line.replace(found, checksum.size(), checksum.size(), '0');
                }
                // add the newline character not read by std::getline
                line.push_back('\n');
                sha256Update(sha256Ctx, line);
            }

            file.close();

            std::string compChecksum = sha256Finalize(sha256Ctx);
            if (compChecksum.compare(checksum) != 0) {
                std::stringstream serr;
                serr << "BMAP checksum invalid" << std::endl;
                serr << "Computed Checksum: " << compChecksum << std::endl;
                serr << "Expected Checksum: " << checksum;
                throw BmapError(serr.str());
            }
        }
    } catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
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

bool isPartitionOf(const std::string& source, const std::string& device)
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
std::string canonicalDevicePath(const std::string& device)
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

int getFreeMemory(size_t *memory, unsigned int divider = 1) {
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

// Minimal RAII guards. The write path has several failure exits and manual
// cleanup after a catch block is easy to get wrong when it grows.
class FdGuard {
public:
    explicit FdGuard(int fd = -1) : fd_(fd) {}
    ~FdGuard() { if (fd_ >= 0) { ::close(fd_); } }
    FdGuard(const FdGuard&) = delete;
    FdGuard& operator=(const FdGuard&) = delete;
    int get() const { return fd_; }
private:
    int fd_;
};

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
static void writeFully(int fd, const char *data, size_t length, off_t offset) {
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

static void readFully(int fd, char *data, size_t length, off_t offset) {
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

static void flushDevice(int fd) {
    if (::fsync(fd) == 0) {
        return;
    }
    // Not every target supports flushing; that is not a write failure.
    if ((errno == EINVAL) || (errno == ENOTSUP)) {
        return;
    }
    throw BmapError(std::string("Failed to flush device: ") + strerror(errno));
}

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
