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
#include <zlib.h>
#include <lzma.h>

#define CHECKSUM_LENGTH 64
#define RANGE_LENGTH    19

#define GZIP_MAGIC_0 0x1f
#define GZIP_MAGIC_1 0x8b
#define XZ_MAGIC_0   0xfd
#define XZ_MAGIC_1   '7'
#define XZ_MAGIC_2   'z'
#define XZ_MAGIC_3   'X'
#define XZ_MAGIC_4   'Z'
#define XZ_MAGIC_5  0x00

#define DEC_BUFFER_SIZE (1024 * 16)

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

int getCompressionType(const std::string &imageFile, std::string &compressionType) {

    std::ifstream file(imageFile, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open image file" << std::endl;
        return -1;
    }

    unsigned char buffer[6];
    file.read(reinterpret_cast<char*>(buffer), 6);
    file.close();

    if (buffer[0] == GZIP_MAGIC_0 && buffer[1] == GZIP_MAGIC_1) {
        compressionType = "gzip";
    } else if (buffer[0] == XZ_MAGIC_0 && buffer[1] == XZ_MAGIC_1 && buffer[2] == XZ_MAGIC_2 &&
               buffer[3] == XZ_MAGIC_3 && buffer[4] == XZ_MAGIC_4 && buffer[5] == XZ_MAGIC_5) {
        compressionType = "xz";
    } else {
        compressionType = "none";
    }

    return 0;
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
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(unsigned char)buffer[i];
        if ((i + 1) % 16 == 0) {
            std::cout << std::endl;
        } else {
            std::cout << " ";
        }
    }
    std::cout << std::endl;
}

int BmapWriteImage(const std::string &imageFile, const bmap_t &bmap, const std::string &device, const std::string &compressionType) {
    gzFile gzImg = nullptr;
    lzma_stream lzmaStream = LZMA_STREAM_INIT;
    std::vector<char> decBufferIn(DEC_BUFFER_SIZE);
    size_t decHead = 0;
    std::ifstream imgFile;
    int dev_fd = -1;
    int ret = 0;

    try {
        dev_fd = open(device.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
        if (dev_fd < 0) {
            throw std::string("Unable to open or create target device");
        }

        if (compressionType == "gzip") {
            gzImg = gzopen(imageFile.c_str(), "rb");
            if (!gzImg) {
                throw std::string("Unable to open gzip image file");
            }
        } else if (compressionType == "xz") {
            imgFile.open(imageFile, std::ios::binary);
            if (!imgFile) {
                throw std::string("Unable to open xz image file");
            }
            lzma_ret ret = lzma_stream_decoder(&lzmaStream, UINT64_MAX, 0);
            if (ret != LZMA_OK) {
                throw std::string("Failed to initialize lzma decoder: ") + std::to_string(static_cast<unsigned int>(ret));
            }

            lzmaStream.avail_in = 0;
        } else if (compressionType == "none") {
            imgFile.open(imageFile, std::ios::binary);
            if (!imgFile) {
                throw std::string("Unable to open image file");
            }
        } else {
            throw std::string("Unsupported compression type ") + compressionType;
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

            if (compressionType == "gzip") {
                gzseek(gzImg, static_cast<off_t>(startBlock * bmap.blockSize), SEEK_SET);
                int readBytes = gzread(gzImg, buffer.data(), static_cast<unsigned int>(bufferSize));
                if (readBytes < 0) {
                    throw std::string("Failed to read from gzip image file");
                }
                outBytes = static_cast<size_t>(readBytes);
            } else if (compressionType == "xz") {
                const size_t outStart = startBlock * bmap.blockSize;
                const size_t outEnd = ((endBlock + 1) * bmap.blockSize);

                // Initialize the output buffer for the decompressor
                lzmaStream.next_out = reinterpret_cast<uint8_t*>(buffer.data());
                lzmaStream.avail_out = static_cast<size_t>(buffer.size());

                while (outBytes < bufferSize) {
                    size_t chunkSize = 0;

                    // Whenever no more input data is available, read some from the compressed file
                    // and reset the input parameters for the decompressor
                    if (lzmaStream.avail_in == 0) {
                        imgFile.read(decBufferIn.data(), static_cast<ssize_t>(decBufferIn.size()));
                        if (imgFile.gcount() == 0 && imgFile.fail()) {
                            throw std::string("Failed to read from xz image file");
                        } else {
                            lzmaStream.next_in = reinterpret_cast<const uint8_t*>(decBufferIn.data());
                            lzmaStream.avail_in = static_cast<size_t>(imgFile.gcount());
                        }
                    }

                    // Save the current status of the output buffer...
                    chunkSize = lzmaStream.avail_out;

                    lzma_ret ret = lzma_code(&lzmaStream, LZMA_RUN);
                    if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
                        throw std::string("Failed to decompress xz image file: ") + std::to_string(static_cast<unsigned int>(ret));
                    }

                    // ...and then extract the size of the decompressed chunk
                    chunkSize -= lzmaStream.avail_out;

                    if (decHead >= outStart && (decHead + chunkSize) <= outEnd) {
                        // Case 1: all decoded data can be used
                        outBytes += chunkSize;
                    } else if (decHead < outStart && (decHead + chunkSize) <= outStart) {
                        // Case 2: all decoded data shall be discarded
                        lzmaStream.next_out = reinterpret_cast<uint8_t*>(buffer.data());
                        lzmaStream.avail_out = static_cast<size_t>(buffer.size());
                    } else if (decHead < outStart && (decHead + chunkSize) > outStart) {
                        // Case 3: only the last portion of the decoded data can be used
                        std::move(buffer.begin() + static_cast<long int>(outStart - decHead),
                                  buffer.begin() + static_cast<long int>(chunkSize),
                                  buffer.begin());
                        size_t validData = chunkSize - (outStart - decHead);
                        outBytes += validData;
                        lzmaStream.next_out = reinterpret_cast<uint8_t*>(buffer.data()) + validData;
                        lzmaStream.avail_out = buffer.size() - validData;
                    }

                    // Advance the head of the decompressed data
                    decHead += chunkSize;

                    // In case all the required data has been decompressed OR the XZ stream is ended
                    // OR the input file has been read completely, stop this decompression loop
                    if ((lzmaStream.avail_out == 0) || (ret == LZMA_STREAM_END) ||
                        (lzmaStream.avail_in == 0 && imgFile.eof())) {
                        break;
                    }
                }
            } else if (compressionType == "none") {
                imgFile.seekg(static_cast<std::streamoff>(startBlock * bmap.blockSize), std::ios::beg);
                imgFile.read(buffer.data(), static_cast<std::streamsize>(bufferSize));
                outBytes = static_cast<size_t>(imgFile.gcount());
                if (outBytes == 0 && imgFile.fail()) {
                    throw std::string("Failed to read from image file");
                }
            }

            // Compute and verify the checksum
            std::string computedChecksum = computeSHA256(buffer, outBytes);
            if (computedChecksum != range.checksum) {
                std::stringstream err;
                err << "Checksum verification failed for range: " << range.range << std::endl;
                err << "Computed Checksum: " << computedChecksum << std::endl;
                err << "Expected Checksum: " << range.checksum;
                //std::cerr << "Buffer content (hex):" << std::endl;
                //printBufferHex(buffer.data(), outBytes);
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
    catch (std::string& err) {
        std::cerr << err << std::endl;
        ret = -1;
    }

    if (dev_fd >= 0) {
        close(dev_fd);
    }

    if (imgFile.is_open()) {
        imgFile.close();
    }

    if (compressionType == "gzip") {
        gzclose(gzImg);
    } else if (compressionType == "xz") {
        lzma_end(&lzmaStream);
    }

    return ret;
}

int main(int argc, char *argv[]) {
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
    int ret=0;
    std::string compressionType;

    ret = getCompressionType(imageFile, compressionType);
    if (ret != 0) {
        std::cerr << "Failed to detect compression type" << std::endl;
        return ret;
    }

    ret = BmapWriteImage(imageFile, bmap, device, compressionType);
    if (ret != 0) {
        std::cerr << "Failed to write image to device" << std::endl;
        return ret;
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "Process completed in " << std::fixed << std::setprecision(2) << elapsed.count() << " seconds." << std::endl;

    return 0;
}
