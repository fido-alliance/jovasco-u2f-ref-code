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

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include <string>
#include <iostream>

#include "u2f.h"
#ifdef _MSC_VER
#include <windows.h>
#else
#include <unistd.h>
#endif

#define CHECK_INFO __FUNCTION__ << "[" << __LINE__ << "]:"

#ifdef PLATFORM_WINDOWS
#	define REDSTART	 (arg_ansi ? "\x1b[31m" : "")
#	define COLOREND  (arg_ansi ? "\x1b[0m"  : "")
#	define GREENSTART (arg_ansi ? "\x1b[32m" : "")
#else
#	define REDSTART	"\x1b[31m"
#	define COLOREND	"\x1b[0m"
#	define GREENSTART "\x1b[32m"
#endif

#define CHECK_2(a, c) { if (!(a)) { std::cerr << REDSTART << __FUNCTION__ << "[" << __LINE__ << "]" << "CHECK_EQ fail at " << CHECK_INFO#a << ":" << c << COLOREND << std::endl; AbortOrNot(); }}
#define CHECK_EQ_3(a,b,c) { if ((a)!=(b)) { std::cerr << REDSTART << __FUNCTION__ << "[" << __LINE__ << "]" << "CHECK_EQ fail at " << CHECK_INFO#a << " != "#b << ": " c << COLOREND << std::endl; AbortOrNot(); }}
#define CHECK_NE_3(a,b,c) { if ((a)==(b)) { std::cerr << REDSTART << __FUNCTION__ << "[" << __LINE__ << "]" << "CHECK_NE fail at " << CHECK_INFO#a << " == "#b << ": " c << COLOREND << std::endl; AbortOrNot(); }}
#define CHECK_GE_3(a,b,c) { if ((a)<(b))  { std::cerr << REDSTART << __FUNCTION__ << "[" << __LINE__ << "]" << "CHECK_GE fail at " << CHECK_INFO#a << " < " #b << ": " c << COLOREND << std::endl; AbortOrNot(); }}
#define CHECK_GT_3(a,b,c) { if ((a)<=(b)) { std::cerr << REDSTART << __FUNCTION__ << "[" << __LINE__ << "]" << "CHECK_GT fail at " << CHECK_INFO#a << " < " #b << ": " c << COLOREND << std::endl; AbortOrNot(); }}
#define CHECK_LT_3(a,b,c) { if ((a)>=(b)) { std::cerr << REDSTART << __FUNCTION__ << "[" << __LINE__ << "]" << "CHECK_LT fail at " << CHECK_INFO#a << " >= "#b << ": " c << COLOREND << std::endl; AbortOrNot(); }}
#define CHECK_LE_3(a,b,c) { if ((a)>(b))  { std::cerr << REDSTART << __FUNCTION__ << "[" << __LINE__ << "]" << "CHECK_LE fail at " << CHECK_INFO#a << " > " #b << ": " c << COLOREND << std::endl; AbortOrNot(); }}

#define CHECK_EQ_2(a,b)  CHECK_EQ_3(a,b,"")
#define CHECK_NE_2(a,b)  CHECK_NE_3(a,b,"")
#define CHECK_GE_2(a,b)  CHECK_GE_3(a,b,"")
#define CHECK_GT_2(a,b)  CHECK_GT_3(a,b,"")
#define CHECK_LT_2(a,b)  CHECK_LT_3(a,b,"")
#define CHECK_LE_2(a,b)  CHECK_LE_3(a,b,"")

#define CHECK_1(a)       CHECK_2(a, "");
#define CHECK_EQ_1       CHECK_1
#define CHECK_NE_1       CHECK_1
#define CHECK_GE_1       CHECK_1
#define CHECK_GT_1       CHECK_1
#define CHECK_LT_1       CHECK_1
#define CHECK_LE_1       CHECK_1

#define EXPAND( a ) a
#define VARGS_(_3, _2, _1, N, ...) N 
#define VARGS(...) EXPAND(VARGS_(__VA_ARGS__, 3, 2, 1, 0))
#define CONCAT_(a, b) a##b
#define CONCAT(a, b) CONCAT_(a, b)
#define INDIRECT_EXPANSION(f, a) f a

#define CHECK(...)    INDIRECT_EXPANSION(CONCAT(CHECK_,   VARGS(__VA_ARGS__)),(__VA_ARGS__))
#define CHECK_EQ(...) INDIRECT_EXPANSION(CONCAT(CHECK_EQ_,VARGS(__VA_ARGS__)),(__VA_ARGS__))
#define CHECK_NE(...) INDIRECT_EXPANSION(CONCAT(CHECK_NE_,VARGS(__VA_ARGS__)),(__VA_ARGS__))
#define CHECK_GE(...) INDIRECT_EXPANSION(CONCAT(CHECK_GE_,VARGS(__VA_ARGS__)),(__VA_ARGS__))
#define CHECK_GT(...) INDIRECT_EXPANSION(CONCAT(CHECK_GT_,VARGS(__VA_ARGS__)),(__VA_ARGS__))
#define CHECK_LT(...) INDIRECT_EXPANSION(CONCAT(CHECK_LT_,VARGS(__VA_ARGS__)),(__VA_ARGS__))
#define CHECK_LE(...) INDIRECT_EXPANSION(CONCAT(CHECK_LE_,VARGS(__VA_ARGS__)),(__VA_ARGS__))

#define PASS(x) { (x == ReturnValue::BLEAPI_ERROR_SUCCESS); std::cout << GREENSTART << "PASS("#x")" << COLOREND << std::endl; }

#define WARN_EQ(a,b) { if ((a)!=(b)) { std::cerr << REDSTART << "WARN_NE fail at " << CHECK_INFO#a << " != "#b << ":" << COLOREND << std::endl; if (arg_LethalWarn) AbortOrNot(); }}


class U2F_info {
 public:
	U2F_info(const char *func, int line) {
		std::cout << " " << func << "[" << line << "]";
	} ~U2F_info() {
		std::cout << std::endl;
	}
	std::ostream & operator<<(const char *s) {
		std::cout << s;
		return std::cout;
	}
};

extern bool arg_Abort;
extern bool arg_Pause;
extern int arg_Verbose;
extern bool arg_LethalWarn;
extern bool arg_ansi;

#define INFO if (arg_Verbose) U2F_info(__FUNCTION__, __LINE__) << ": "

std::string bytes2ascii(const char *ptr, int len);
std::string bytes2ascii(const std::string & s);

uint16_t bytes2short(const unsigned char *buffer, uint32_t offset);

void AbortOrNot();

bool getCertificate(const U2F_REGISTER_RESP & rsp, std::string * cert);
bool getSignature(const U2F_REGISTER_RESP & rsp, int certsize,
		  std::string * sig);
bool getSubjectPublicKey(const std::string & cert, std::string * pk);
