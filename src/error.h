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

#ifndef BMAP_ERROR_H
#define BMAP_ERROR_H

#include <stdexcept>
#include <string>

// All recoverable failures are reported by throwing this type. Using a
// dedicated exception (rather than std::string) keeps the catch handlers
// compatible with the exceptions thrown by the standard library itself,
// e.g. std::invalid_argument from std::stoull or std::bad_alloc.
struct BmapError : public std::runtime_error {
    explicit BmapError(const std::string& what) : std::runtime_error(what) {}
};

#endif // BMAP_ERROR_H
