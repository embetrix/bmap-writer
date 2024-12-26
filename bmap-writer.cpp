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
#include <cstring>
#include <cerrno>

#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <openssl/evp.h>
#include <archive.h>


struct range_t {
    std::string checksum;
    size_t startBlock;
    size_t endBlock;
};

struct bmap_t {
    std::vector<range_t> ranges;
    size_t blockSize;
};

struct checksum_t {
    EVP_MD_CTX *mdctx;
    unsigned char checksum[EVP_MAX_MD_SIZE];
    unsigned int checksum_len;
};

static void checksumDeinit(struct checksum_t* checksum)
{
    if (checksum->mdctx) {
        EVP_MD_CTX_free(checksum->mdctx);
        checksum->mdctx = nullptr;
    }
}

static bool checksumInit(struct checksum_t* checksum)
{
    int success = false;

    checksum->checksum_len = 0;
    checksum->mdctx = EVP_MD_CTX_new();
    if (checksum->mdctx != nullptr) {
        int ret = EVP_DigestInit_ex(checksum->mdctx, EVP_sha256(), nullptr);
        success = (ret == 1);
    }

    return success;
}

static void checksumUpdate(struct checksum_t* checksum, const std::vector<char>& buffer, size_t size)
{
    EVP_DigestUpdate(checksum->mdctx, buffer.data(), size);
}

static int checksumFinish(struct checksum_t* checksum)
{
    int ret = EVP_DigestFinal_ex(checksum->mdctx, checksum->checksum, &checksum->checksum_len);
    return (ret == 1);
}

static std::string checksumGetString(struct checksum_t* checksum) {
    std::ostringstream output;
    output << std::hex;
    for (unsigned int i = 0; i < checksum->checksum_len; ++i) {
        output << std::setfill('0') << std::setw(2) << static_cast<unsigned int>(checksum->checksum[i]);
    }
    return output.str();
};

bmap_t parseBMap(const std::string &filename) {
    bmap_t bmapData = {};
    bmapData.blockSize = 0;

    xmlDocPtr doc = xmlReadFile(filename.c_str(), NULL, 0);
    if (doc == NULL) {
        return bmapData;
    }

    xmlNodePtr root_element = xmlDocGetRootElement(doc);
    for (xmlNodePtr node = root_element->children; node; node = node->next) {
        if (node->type == XML_ELEMENT_NODE) {
            if (strcmp(reinterpret_cast<const char *>(node->name), "BlockSize") == 0) {
                xmlChar *blockSizeStr = xmlNodeGetContent(node);
                bmapData.blockSize = static_cast<size_t>(std::stoul(reinterpret_cast<const char *>(blockSizeStr)));
                xmlFree(blockSizeStr);
                //std::cout << "BlockSize: " << bmapData.blockSize << std::endl;
            } else if (strcmp(reinterpret_cast<const char *>(node->name), "BlockMap") == 0) {
                for (xmlNodePtr rangeNode = node->children; rangeNode; rangeNode = rangeNode->next) {
                    if (rangeNode->type == XML_ELEMENT_NODE && strcmp(reinterpret_cast<const char *>(rangeNode->name), "Range") == 0) {
                        xmlChar *checksum = xmlGetProp(rangeNode, reinterpret_cast<const xmlChar *>("chksum"));
                        xmlChar *range = xmlNodeGetContent(rangeNode);

                        range_t r;
                        r.checksum = reinterpret_cast<const char *>(checksum);

                        if (sscanf(reinterpret_cast<const char *>(range), "%zu-%zu", &r.startBlock, &r.endBlock) == 1) {
                            r.endBlock = r.startBlock;  // Handle single block range
                        }

                        bmapData.ranges.push_back(r);
                        //std::cout << "Parsed Range: checksum=" << r.checksum << ", range=" << r.range << std::endl;
                        xmlFree(checksum);
                        xmlFree(range);
                    }
                }
            }
        }
    }

    xmlFreeDoc(doc);
    xmlCleanupParser();

    return bmapData;
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

int BmapWriteImage(const std::string &imageFile, const bmap_t &bmap, const std::string &device, bool noVerify) {
    struct archive *a = nullptr;
    checksum_t checksum;
    int dev_fd = -1;
    int ret = 0;

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

        int r = archive_read_open_filename(a, imageFile.c_str(), READ_BLK_SIZE);
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
            throw std::string("Failed to read archive header: ") + std::string(archive_error_string(a));
        }

        for (const auto &range : bmap.ranges) {
            //std::cout << "Processing Range: startBlock=" << range.startBlock << ", endBlock=" << range.endBlock << std::endl;
            const size_t outStart = range.startBlock * bmap.blockSize;
            const size_t outEnd = ((range.endBlock + 1) * bmap.blockSize);
            const size_t rangeSize = (range.endBlock - range.startBlock + 1) * bmap.blockSize;
            const off_t writeOffset = static_cast<off_t>(range.startBlock * bmap.blockSize);
            size_t maxBufferSize = 0;
            size_t writtenSize = 0;
            bool endOfFile = false;

            if (!noVerify) {
                if (!checksumInit(&checksum)) {
                    throw std::string("Failed to init checksum engine");
                }
            }

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
            }

            if (!noVerify) {
                // Read back written data and compute checksum on it.
                size_t readSize = 0;
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

                    checksumUpdate(&checksum, buffer, buffer.size());

                    readSize += static_cast<size_t>(readData);
                }

                if (!checksumFinish(&checksum)) {
                    throw std::string("Failed to compute SHA256 checksum");
                } else if (checksumGetString(&checksum).compare(range.checksum) != 0) {
                    std::stringstream err;
                    err << "Read-back verification failed for range: " << range.startBlock << " - " << range.endBlock << std::endl;
                    err << "Read Checksum: " << checksumGetString(&checksum) << std::endl;
                    err << "Expected Checksum: " << range.checksum;
                    throw std::string(err.str());
                }

                checksumDeinit(&checksum);
            }
        }

        std::cout << "Finished writing image to device: " << device << std::endl;
        if (noVerify) {
            std::cout << "Checksum verification skipped." << std::endl;
        }
    }
    catch (const std::string& err) {
        std::cerr << err << std::endl;
        ret = -1;
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
    std::cerr << "Usage: " << progname << " "
              << "[-hn] <image-file> <bmap-file> <target-device>" << std::endl;
    std::cerr << std::endl;
    std::cerr << "-n : Skip checksum verification" << std::endl;
    std::cerr << "-h : Show this help and exit" << std::endl;
}

int main(int argc, char *argv[]) {
    bool noVerify = false;
    int opt;

    while ((opt = getopt(argc, argv, "hn")) != -1) {
        switch (opt) {
            case 'n':
                noVerify = true;
                break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            default:
                std::cerr << "Unknown option -" << static_cast<char>(opt) << std::endl;
                printUsage(argv[0]);
                return -1;
        }
    }

    if ((argc - optind) < 2 || (argc - optind) > 4) {
        std::cerr << "Wrong number of args" << std::endl;
        printUsage(argv[0]);
        return -1;
    }

    std::string imageFile = argv[optind];
    std::string bmapFile;
    std::string device;

    if ((argc - optind) == 3) {
        bmapFile = argv[optind + 1];
        device = argv[optind + 2];
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
            return 1;
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
        return 1;
    }
    auto start = std::chrono::high_resolution_clock::now();
    bmap_t bmap = parseBMap(bmapFile);
    if (bmap.blockSize == 0 || bmap.ranges.empty()) {
        std::cerr << "Failed to parse file: " << bmapFile << std::endl;
        return 1;
    }
    int ret = BmapWriteImage(imageFile, bmap, device, noVerify);
    if (ret != 0) {
        std::cerr << "Failed to write image to device: " << device << std::endl;
        return ret;
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "Process completed in " << std::fixed << std::setprecision(2) << elapsed.count() << " seconds." << std::endl;

    return 0;
}
