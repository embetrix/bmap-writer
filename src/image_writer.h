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

#ifndef BMAP_IMAGE_WRITER_H
#define BMAP_IMAGE_WRITER_H

#include <string>

struct bmap_t;

// Decompress the input, write mapped ranges, and optionally verify read-back.
// The caller owns both descriptors and must validate the BMAP first.
int BmapWriteImage(int fd, const bmap_t& bmap, int dev_fd,
                   const std::string& device, bool noVerify);

#endif // BMAP_IMAGE_WRITER_H
