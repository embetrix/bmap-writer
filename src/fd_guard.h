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

#ifndef BMAP_FD_GUARD_H
#define BMAP_FD_GUARD_H

#include <unistd.h>

// Owns a file descriptor and closes it on every exit path.
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

#endif // BMAP_FD_GUARD_H
