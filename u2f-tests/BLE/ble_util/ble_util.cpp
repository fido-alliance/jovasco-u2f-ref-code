/*
 *   Copyright (C) 2016, VASCO Data Security Int.
 *   Copyright 2014 Google Inc. All rights reserved.
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
 *
 *   This file is based heavily on 
 *   https://github.com/google/u2f-ref-code/blob/master/u2f-tests/HID/u2f_util.c
 */

#include "ble_util.h"

#ifdef PLATFORM_WINDOWS
bool arg_ansi = false;
#else
bool arg_ansi = true;
#endif

bool arg_Abort = true;		// default
bool arg_Pause = false;		// default
bool arg_LethalWarn = false;	// default

std::string b2a(const void *ptr, size_t size)
{
	const uint8_t *p = reinterpret_cast < const uint8_t * >(ptr);
	std::string result;

	for (size_t i = 0; i < 2 * size; ++i) {
		int nib = p[i / 2];
		if ((i & 1) == 0)
			nib >>= 4;
		nib &= 15;
		result.push_back("0123456789ABCDEF"[nib]);
	}

	return result;
}

std::string b2a(const std::string & s)
{
	return b2a(s.data(), s.size());
}

std::string a2b(const std::string & s)
{
	std::string result;
	int v;
	for (size_t i = 0; i < s.size(); ++i) {
		if ((i & 1) == 1)
			v <<= 4;
		else
			v = 0;
		char d = s[i];
		if (d >= '0' && d <= '9')
			v += (d - '0');
		else if (d >= 'A' && d <= 'F')
			v += (d - 'A' + 10);
		else if (d >= 'a' && d <= 'f')
			v += (d - 'a' + 10);
		if ((i & 1) == 1)
			result.push_back(v & 255);
	}
	return result;
}

void checkPause()
{
	if (arg_Pause) {
		printf("\nPress any key to continue..");
		getchar();
		printf("\n");
	}
}

void AbortOrNot()
{
	checkPause();
	if (arg_Abort)
		abort();
	std::cerr << "(continuing -a)" << std::endl;
}

uint16_t b2s(const unsigned char *buffer, uint32_t offset)
{
	return (uint16_t) (((uint16_t) buffer[offset] << 8) | (uint16_t)
			   buffer[offset + 1]);
}

bool getCertificate(const U2F_REGISTER_RESP & rsp, std::string * cert)
{
	size_t hkLen = rsp.keyHandleLen;

	CHECK_GE(hkLen, 64);
	CHECK_LT(hkLen, sizeof(rsp.keyHandleCertSig));

	size_t certOff = hkLen;
	size_t certLen = sizeof(rsp.keyHandleCertSig) - certOff;
	const uint8_t *p = &rsp.keyHandleCertSig[certOff];

	CHECK_GE(certLen, 4);
	CHECK_EQ(p[0], 0x30);

	CHECK_GE(p[1], 0x81);
	CHECK_LE(p[1], 0x82);

	size_t seqLen;
	size_t headerLen;
	if (p[1] == 0x81) {
		seqLen = p[2];
		headerLen = 3;
	} else if (p[1] == 0x82) {
		seqLen = p[2] * 256 + p[3];
		headerLen = 4;
	} else {
		// FAIL
		AbortOrNot();
	}

	CHECK_LE(seqLen, certLen - headerLen);

	cert->assign(reinterpret_cast < const char *>(p), seqLen + headerLen);
	return true;
}

bool getSignature(const U2F_REGISTER_RESP & rsp, std::string * sig)
{
	std::string cert;
	CHECK_NE(false, getCertificate(rsp, &cert));

	size_t sigOff = rsp.keyHandleLen + cert.size();
	CHECK_LE(sigOff, sizeof(rsp.keyHandleCertSig));

	size_t sigLen = sizeof(rsp.keyHandleCertSig) - sigOff;
	const uint8_t *p = &rsp.keyHandleCertSig[sigOff];

	CHECK_GE(sigLen, 2);
	CHECK_EQ(p[0], 0x30);

	size_t seqLen = p[1];
	CHECK_LE(seqLen, sigLen - 2);

	sig->assign(reinterpret_cast < const char *>(p), seqLen + 2);
	return true;
}

bool getSubjectPublicKey(const std::string & cert, std::string * pk)
{
	CHECK_GE(cert.size(), P256_POINT_SIZE);

	// Explicitly search for asn1 lead-in sequence of p256-ecdsa public key.
	const char asn1[] =
	    "3059301306072A8648CE3D020106082A8648CE3D030107034200";
	std::string pkStart(a2b(asn1));

	size_t off = cert.find(pkStart);
	CHECK_NE(off, std::string::npos);

	off += pkStart.size();
	CHECK_LE(off, cert.size() - P256_POINT_SIZE);

	pk->assign(cert, off, P256_POINT_SIZE);
	return true;
}
