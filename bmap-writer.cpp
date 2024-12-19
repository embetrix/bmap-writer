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
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <openssl/evp.h>
#include <archive.h>

#define CHECKSUM_LENGTH 64
#define RANGE_LENGTH    19

struct range_t {
    std::string checksum;
    std::string range;
};

struct bmap_t {
    std::vector<range_t> ranges;
    size_t blockSize;
};

bmap_t parseBMap(const std::string &filename) {
    bmap_t bmapData = {};
    bmapData.blockSize = 0;

    xmlDocPtr doc = xmlReadFile(filename.c_str(), NULL, 0);
    if (doc == NULL) {
        std::cerr << "Failed to parse " << filename << std::endl;
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
                        r.range = reinterpret_cast<const char *>(range);

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

std::string computeSHA256(const std::vector<char>& buffer, size_t size) {
    EVP_MD_CTX *mdctx;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, buffer.data(), size);
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    std::ostringstream output;
    output << std::hex;
    for (unsigned int i = 0; i < hash_len; ++i) {
        output << std::setfill('0') << std::setw(2) << static_cast<unsigned int>(hash[i]);
    }

    return output.str();
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

void printBufferHex(const char *buffer, size_t size) {
#ifdef DEBUG
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(unsigned char)buffer[i];
        if ((i + 1) % 16 == 0) {
            std::cout << std::endl;
        } else {
            std::cout << " ";
        }
    }
    std::cout << std::endl;
#else
    (void)buffer;
    (void)size;
    return;
#endif
}

int BmapWriteImage(const std::string &imageFile, const bmap_t &bmap, const std::string &device) {
    static const size_t read_block_size = 16384;
    struct archive *a = nullptr;
    int dev_fd = -1;
    int ret = 0;

    try {
        size_t decHead = 0;

        dev_fd = open(device.c_str(), O_WRONLY | O_CREAT | O_SYNC, S_IRUSR | S_IWUSR);
        if (dev_fd < 0) {
            throw std::string("Unable to open or create target device");
        }

        a = archive_read_new();

        /* Support all compression types */
        archive_read_support_filter_all(a);

        /* Support a single compressed file or tar archive */
        archive_read_support_format_raw(a);
        archive_read_support_format_tar(a);

        int r = archive_read_open_filename(a, imageFile.c_str(), read_block_size);
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
            size_t startBlock, endBlock;
            if (sscanf(range.range.c_str(), "%zu-%zu", &startBlock, &endBlock) == 1) {
                endBlock = startBlock;  // Handle single block range
            }
            //std::cout << "Processing Range: startBlock=" << startBlock << ", endBlock=" << endBlock << std::endl;

            size_t bufferSize = (endBlock - startBlock + 1) * bmap.blockSize;
            std::vector<char> buffer(bufferSize);
            size_t outBytes = 0;

            const size_t outStart = startBlock * bmap.blockSize;
            const size_t outEnd = ((endBlock + 1) * bmap.blockSize);

            while (outBytes < bufferSize) {
                ssize_t readData = archive_read_data(a, buffer.data() + outBytes, bufferSize - outBytes);

                // If no more data is available in the input buffer and the input file has been
                // read completely, stop this decompression loop
                if (readData <= 0)
                    break;

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

            // Compute and verify the checksum
            std::string computedChecksum = computeSHA256(buffer, outBytes);
            if (computedChecksum != range.checksum) {
                std::stringstream err;
                err << "Checksum verification failed for range: " << range.range << std::endl;
                err << "Computed Checksum: " << computedChecksum << std::endl;
                err << "Expected Checksum: " << range.checksum;
                //std::cerr << "Buffer content (hex):" << std::endl;
                printBufferHex(buffer.data(), outBytes);
                throw std::string(err.str());
            }

            if (pwrite(dev_fd, buffer.data(), outBytes, static_cast<off_t>(startBlock * bmap.blockSize)) < 0) {
                throw std::string("Write to device failed");
            }
        }

        if (fsync(dev_fd) != 0) {
            throw std::string("fsync failed after all writes");
        }

        std::cout << "Finished writing image to device." << std::endl;
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

int main(int argc, const char *argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <image-file> <bmap-file> <target-device>" << std::endl;
        return 1;
    }

    std::string imageFile = argv[1];
    std::string bmapFile = argv[2];
    std::string device = argv[3];

    std::cout << "Starting bmap writer..." << std::endl;
    if (isDeviceMounted(device)) {
        std::cerr << "Error: Device " << device << " is mounted. Please unmount it before proceeding." << std::endl;
        return 1;
    }
    auto start = std::chrono::high_resolution_clock::now();
    bmap_t bmap = parseBMap(bmapFile);
    if (bmap.blockSize == 0) {
        std::cerr << "BlockSize not found in BMAP file" << std::endl;
        return 1;
    }
    int ret = BmapWriteImage(imageFile, bmap, device);
    if (ret != 0) {
        std::cerr << "Failed to write image to device" << std::endl;
        return ret;
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "Process completed in " << std::fixed << std::setprecision(2) << elapsed.count() << " seconds." << std::endl;

    return 0;
}
