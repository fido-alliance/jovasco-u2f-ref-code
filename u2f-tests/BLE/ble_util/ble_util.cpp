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

#include "ble_util.h"

#ifdef PLATFORM_WINDOWS
bool arg_ansi = false;
#else
bool arg_ansi = true;
#endif

bool arg_Abort = true;		// default
bool arg_Pause = false;		// default
bool arg_LethalWarn = false;	// default

std::string bytes2ascii(const char *ptr, int len)
{
	static const char *convert = "0123456789ABCDEF";
	std::string r;
	int i;

	for (i = 0; i < len; i++) {
		const char c = ptr[i];

		r += convert[(c >> 4) & 0x0F];
		r += convert[(c) & 0x0F];
	}

	return r;
}

std::string bytes2ascii(const std::string & s)
{
	return bytes2ascii(s.data(), s.size());
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

uint16_t bytes2short(const unsigned char *buffer, uint32_t offset)
{
	return (((uint16_t) (buffer[offset] << 8)) | (uint16_t)
		buffer[offset + 1]);
}

bool getCertificate(const U2F_REGISTER_RESP & rsp, std::string * cert)
{
	int len = rsp.keyHandleLen;
	int certlen = MAX_KH_SIZE + MAX_CERT_SIZE + MAX_ECDSA_SIG_SIZE - len;

	unsigned char *p = (unsigned char *)&rsp.keyHandleCertSig[len];

	CHECK_GE(certlen, 4 + 25);	// must be larger than the header we test + the asn sequence for the public key (see below)
	CHECK_EQ(p[0], 0x30);

	int seqlen, headerlen;
	switch (p[1]) {
	case 0x81:
		seqlen = p[2];
		headerlen = 3;
		break;
	case 0x82:
		seqlen = p[2] * 256 + p[3];
		headerlen = 4;
		break;
	default:
		CHECK_GE(p[1], 0x81);
		CHECK_LE(p[1], 0x82);
		return false;
	}

	CHECK_LE(seqlen, certlen - headerlen);

	cert->assign(reinterpret_cast < const char *>(p), seqlen + headerlen);
	return true;
}

bool getSignature(const U2F_REGISTER_RESP & rsp, int certsize,
		  std::string * sig)
{
	int sigoffset = rsp.keyHandleLen + certsize;
	CHECK_LE(sigoffset, MAX_KH_SIZE + MAX_CERT_SIZE + MAX_ECDSA_SIG_SIZE);

	size_t siglength = sizeof(rsp.keyHandleCertSig) - sigoffset;
	const unsigned char *p = &rsp.keyHandleCertSig[sigoffset];

	CHECK_GE(siglength, 2);	// why 2?
	CHECK_EQ(p[0], 0x30);	// start of signature

	// extract and check length
	size_t seqlen = p[1];
	CHECK_LE(seqlen, siglength - 2);

	sig->assign(reinterpret_cast < const char *>(p), seqlen + 2);
	return true;
}

bool getSubjectPublicKey(const std::string & cert, std::string * pk)
{
	CHECK_GE(cert.size(), P256_POINT_SIZE);

	// Explicitly search for asn1 lead-in sequence of p256-ecdsa public key.
	const unsigned char asn1[] = {
		0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
		0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
		0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
		0x42, 0x00
	};

	// see if this sequence is part of the certificate
	size_t off = cert.find((const char *)asn1, 0, sizeof(asn1));
	CHECK_NE(off, std::string::npos);

	// see if the cert has at least the pointsize length left.
	off += sizeof(asn1);
	CHECK_LE(off, cert.size() - P256_POINT_SIZE);

	pk->assign(cert, off, P256_POINT_SIZE);

	return true;
}
