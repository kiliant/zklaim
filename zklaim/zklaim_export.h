/*
 * This file is part of zklaim.
 * zklaim is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * zklaim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with zklaim. If not, see https://www.gnu.org/licenses/.
 */

#ifndef ZKLAIM_EXPORT_H
#define ZKLAIM_EXPORT_H

// libzklaim is built with hidden visibility; only functions marked with
// ZKLAIM_API are exported from the shared library.
#if defined(__GNUC__) || defined(__clang__)
#define ZKLAIM_API __attribute__((visibility("default")))
#else
#define ZKLAIM_API
#endif

#endif // ZKLAIM_EXPORT_H
