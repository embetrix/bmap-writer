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
#include "error.h"
#include "sha256.h"

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>

#include <tinyxml2.h>

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
