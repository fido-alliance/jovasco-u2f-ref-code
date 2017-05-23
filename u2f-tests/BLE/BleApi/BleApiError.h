/*
 *   Copyright (C) 2016, VASCO Data Security Int.
 *   Author: Johan.Verrept@vasco.com
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _BLEAPI_BLEAPIERROR_H_
#define _BLEAPI_BLEAPIERROR_H_

// we need a C++11 compiler. MSVC2015 supports this but not C++11.
#if (__cplusplus >= 201103L)||(_MSC_VER >= 1700)
#define _ENUM_CLASS_  class
#else
#define _ENUM_CLASS_
#endif

typedef enum _ENUM_CLASS_ ReturnValue {
	BLEAPI_ERROR_SUCCESS = 0,
	BLEAPI_ERROR_UNKNOWN_ERROR,
	BLEAPI_ERROR_NOT_IMPLEMENTED,
	BLEAPI_ERROR_BAD_REPLY,
	BLEAPI_ERROR_BAD_SEQUENCE,
	BLEAPI_ERROR_BUFFER_TOO_SMALL,
	BLEAPI_ERROR_REPLY_TOO_LONG,
	BLEAPI_ERROR_OUTOFMEMORY,
	BLEAPI_ERROR_INVALID_PARAMETER,
	BLEAPI_ERROR_NOT_FOUND,
	BLEAPI_ERROR_TIMEOUT,
} ReturnValue;

inline bool operator!(ReturnValue r) { return (r != ReturnValue::BLEAPI_ERROR_SUCCESS); };

#endif				/* _BLEAPI_BLEAPIERROR_H_ */
