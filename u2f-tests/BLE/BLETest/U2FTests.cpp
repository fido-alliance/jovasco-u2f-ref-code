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

#include "u2f.h"

#include "U2FTests.h"

#include "../BleApi/fido_ble.h"
#include "../BleApi/fido_apduresponses.h"

#include "mincrypt/dsa_sig.h"
#include "mincrypt/p256.h"
#include "mincrypt/p256_ecdsa.h"
#include "mincrypt/sha256.h"

//#define REPLY_BUFFER_LENGTH 256
//static unsigned char reply[REPLY_BUFFER_LENGTH];
//static unsigned int replyLength = REPLY_BUFFER_LENGTH;

ReturnValue BleApiTest_GetU2FProtocolVersion(pBleDevice dev)
{
	ReturnValue retval;

	/* write U2F VERSION command to get U2F protocol version */
	unsigned char request[] = { 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char reply[256];
	unsigned int replyLength = sizeof(reply);
	unsigned char replyCmd;
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_MSG, request, 7, &replyCmd, reply,
			      &replyLength);
	if (!retval)
		return retval;

	/* drop reply status code. */
	reply[replyLength - 2] = '\0';

	/* check U2F Protocol version */
	CHECK_EQ((replyLength - 2), 6);
	CHECK_EQ(memcmp(reply, "U2F_V2", 6), 0);

	INFO << "U2F Version: " << reply;

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_UnknownINS(pBleDevice dev)
{
	ReturnValue retval;

	/* write U2F VERSION command to get U2F protocol version */
	unsigned char request[] =
	    { 0x00, 0x00 /* not U2F instruction */ , 0x00, 0x00, 0x00, 0x00,
		0x00
	};
	unsigned char reply[256];
	unsigned int replyLength = sizeof(reply);
	unsigned char replyCmd;
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_MSG, request, 7, &replyCmd, reply,
			      &replyLength);
	if (!retval)
		return retval;

	/* check reply */
	CHECK_EQ(replyLength, 2);
	CHECK_EQ(FIDO_RESP_INVALID_INSTRUCTION, bytes2short(reply, 0));

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_BadCLA(pBleDevice dev)
{
	ReturnValue retval;

	/* write U2F VERSION command to get U2F protocol version */
	unsigned char request[] =
	    { 0x01 /* != 0 */ , 0x03, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char reply[256];
	unsigned int replyLength = sizeof(reply);
	unsigned char replyCmd;

	request[0] = 0x01 + (rand() % 0xFF);

	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_MSG, request, 7, &replyCmd, reply,
			      &replyLength);
	if (!retval)
		return retval;

	/* check reply */
	CHECK_EQ(replyLength, 2);
	CHECK_NE(FIDO_RESP_SUCCESS, bytes2short(reply, 0));

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_VersionWrongLength(pBleDevice dev)
{
	ReturnValue retval;

	/* write U2F VERSION command to get U2F protocol version */
	unsigned char request[] =
	    { 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03 };
	unsigned char reply[256];
	unsigned int replyLength = sizeof(reply);
	unsigned char replyCmd;
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_MSG, request, 10, &replyCmd, reply,
			      &replyLength);
	if (!retval)
		return retval;

	/* check reply */
	CHECK_EQ(replyLength, 2);
	CHECK_EQ(FIDO_RESP_WRONG_LENGTH, bytes2short(reply, 0));

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_RegisterWrongLength(pBleDevice dev)
{
	ReturnValue retval;

	/* write U2F VERSION command to get U2F protocol version */
	unsigned char request[] =
	    { 0x00, 0x01 /* register */ , 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x02, 0x03
	};
	unsigned char reply[256];
	unsigned int replyLength = sizeof(reply);
	unsigned char replyCmd;
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_MSG, request, 10, &replyCmd, reply,
			      &replyLength);
	if (!retval)
		return retval;

	/* check reply */
	CHECK_EQ(replyLength, 2);
	CHECK_EQ(FIDO_RESP_WRONG_LENGTH, bytes2short(reply, 0));

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

U2F_REGISTER_RESP regRsp;
U2F_REGISTER_REQ regReq;

ReturnValue BleApiTest_Enroll(pBleDevice dev, int expectedSW12)
{
	uint64_t t = dev->TimeMs();

	ReturnValue retval;
	int i;
	unsigned char reply[2048];
	unsigned int replyLength = sizeof(reply);
	unsigned char request[256];
	unsigned int requestlen;
	unsigned char replyCmd;

	memset(reply, 0, sizeof(reply));

	/* generate appid and nonce */
	for (i = 0; i < sizeof(regReq.appId); i++)
		regReq.appId[i] = (rand() & 0xFF);
	for (i = 0; i < sizeof(regReq.nonce); i++)
		regReq.nonce[i] = (rand() & 0xFF);

	/* prepare register request */
	request[0] = 0x00;
	request[1] = 0x01;
	request[2] = 0x00;
	request[3] = 0x00;
	request[4] = 0x00;
	request[5] = 0x00;
	request[6] = sizeof(regReq.nonce) + sizeof(regReq.appId);
	memcpy(request + 7, regReq.nonce, sizeof(regReq.nonce));
	memcpy(request + 7 + sizeof(regReq.nonce), regReq.appId,
	       sizeof(regReq.appId));
	requestlen = 7 + sizeof(regReq.nonce) + sizeof(regReq.appId);
	request[requestlen++] = 0x00;
	request[requestlen++] = 0x00;

	/* write command */
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_MSG, request, requestlen, &replyCmd,
			      reply, &replyLength);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	if (expectedSW12 != FIDO_RESP_SUCCESS) {
		CHECK_EQ(expectedSW12, bytes2short(reply, replyLength - 2));
		CHECK_EQ(replyLength, 2);
		return ReturnValue::BLEAPI_ERROR_SUCCESS;
	}

	/* check reply */
	CHECK_EQ(replyCmd, FIDO_BLE_CMD_MSG);
	CHECK_EQ(FIDO_RESP_SUCCESS, bytes2short(reply, replyLength - 2));
	CHECK_NE(replyLength, 2);

	CHECK_LE(replyLength - 2, sizeof(U2F_REGISTER_RESP));

	memcpy(&regRsp, reply, replyLength - 2);

	CHECK_EQ(regRsp.registerId, U2F_REGISTER_ID);
	CHECK_EQ(regRsp.pubKey.format, UNCOMPRESSED_POINT);

	INFO << "Enroll: " << (replyLength -
			       2) << " bytes in " << ((float)(dev->TimeMs() -
							      t)) /
	    1000.0 << "s";

	// Check crypto of enroll response.
	std::string cert;
	CHECK_EQ(getCertificate(regRsp, &cert), true);
	INFO << "cert: " << bytes2ascii(cert);

	std::string pk;
	CHECK_EQ(getSubjectPublicKey(cert, &pk), true);
	INFO << "pk  : " << bytes2ascii(pk);

	std::string sig;
	CHECK_EQ(getSignature(regRsp, static_cast<int>(cert.size()), &sig), true);
	INFO << "sig : " << bytes2ascii(sig);

	// Parse signature into two integers.
	p256_int sig_r, sig_s;
	CHECK_EQ(1, dsa_sig_unpack((uint8_t *) (sig.data()), static_cast<int>(sig.size()),
				   &sig_r, &sig_s));

	// Compute hash as integer.
	const uint8_t *hash;
	p256_int h;
	SHA256_CTX sha;
	SHA256_init(&sha);
	uint8_t rfu = 0;
	SHA256_update(&sha, &rfu, sizeof(rfu));	// 0x00
	SHA256_update(&sha, regReq.appId, sizeof(regReq.appId));	// O
	SHA256_update(&sha, regReq.nonce, sizeof(regReq.nonce));	// d
	SHA256_update(&sha, regRsp.keyHandleCertSig, regRsp.keyHandleLen);	// hk
	SHA256_update(&sha, &regRsp.pubKey, sizeof(regRsp.pubKey));	// pk
	hash = SHA256_final(&sha);
	p256_from_bin(hash, &h);

	INFO << "hash : " << bytes2ascii((char *)hash, 32);

	// Parse subject public key into two integers.
	CHECK_EQ(pk.size(), P256_POINT_SIZE);
	p256_int pk_x, pk_y;
	p256_from_bin((uint8_t *) pk.data() + 1, &pk_x);
	p256_from_bin((uint8_t *) pk.data() + 1 + P256_SCALAR_SIZE, &pk_y);

	// Verify signature.
	CHECK_EQ(1, p256_ecdsa_verify(&pk_x, &pk_y, &h, &sig_r, &sig_s));

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_Sign(pBleDevice dev, uint32_t *ctr, int expectedSW12, bool checkOnly,
			 bool corruptKH, bool corruptAddId)
{
	ReturnValue retval;

	U2F_AUTHENTICATE_REQ authReq;
	unsigned char reply[2048];
	unsigned int replyLength = sizeof(reply);
	unsigned char request[256];
	unsigned int requestlen;
	unsigned char replyCmd;

	// pick random challenge and use registered appId.
	for (size_t i = 0; i < sizeof(authReq.nonce); ++i)
		authReq.nonce[i] = rand();
	memcpy(authReq.appId, regReq.appId, sizeof(authReq.appId));
	authReq.keyHandleLen = regRsp.keyHandleLen;
	memcpy(authReq.keyHandle, regRsp.keyHandleCertSig,
	       authReq.keyHandleLen);

	if (corruptKH)
		authReq.keyHandle[0] ^= 0x55;
	if (corruptAddId)
		authReq.appId[0] ^= 0xAA;

	uint64_t t = dev->TimeMs();

	/* prepare register request */
	request[0] = 0x00;
	request[1] = U2F_INS_AUTHENTICATE;
	request[2] = checkOnly ? U2F_AUTH_CHECK_ONLY : U2F_AUTH_ENFORCE;
	request[3] = 0x00;
	request[4] = 0x00;
	request[5] = 0x00;
	request[6] = U2F_NONCE_SIZE + U2F_APPID_SIZE + 1 + authReq.keyHandleLen;
	memcpy(request + 7, reinterpret_cast < char *>(&authReq), request[6]);
	requestlen = 7 + request[6];
	request[requestlen++] = 0x00;
	request[requestlen++] = 0x00;

	/* write command */
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_MSG, request, requestlen, &replyCmd,
			      reply, &replyLength);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	if (expectedSW12 != FIDO_RESP_SUCCESS) {
		CHECK_EQ(expectedSW12, bytes2short(reply, replyLength - 2));
		CHECK_EQ(replyLength, 2);
		return ReturnValue::BLEAPI_ERROR_SUCCESS;
	}

	CHECK_EQ(replyCmd, FIDO_BLE_CMD_MSG);
	CHECK_EQ(FIDO_RESP_SUCCESS, bytes2short(reply, replyLength - 2));
	CHECK_NE(replyLength, 2);
	CHECK_LE(replyLength - 2, sizeof(U2F_AUTHENTICATE_RESP));

	U2F_AUTHENTICATE_RESP resp;
	memcpy(&resp, reply, replyLength - 2);

	CHECK_EQ(resp.flags, 0x01);

	INFO << "Sign: " << (replyLength - 2) << " bytes in "
	    << ((float)(dev->TimeMs() - t)) / 1000.0 << "s";

	// Parse signature from authenticate response.
	p256_int sig_r, sig_s;
	CHECK_EQ(1, dsa_sig_unpack(resp.sig,
				   replyLength - 2 - sizeof(resp.flags) -
				   sizeof(resp.ctr), &sig_r, &sig_s));

	// Compute hash as integer.
	p256_int h;
	SHA256_CTX sha;
	SHA256_init(&sha);
	SHA256_update(&sha, regReq.appId, sizeof(regReq.appId));	// O
	SHA256_update(&sha, &resp.flags, sizeof(resp.flags));	// T
	SHA256_update(&sha, &resp.ctr, sizeof(resp.ctr));	// CTR
	SHA256_update(&sha, authReq.nonce, sizeof(authReq.nonce));	// d
	p256_from_bin(SHA256_final(&sha), &h);

	// Parse public key from registration response.
	p256_int pk_x, pk_y;
	p256_from_bin(regRsp.pubKey.x, &pk_x);
	p256_from_bin(regRsp.pubKey.y, &pk_y);

	// Verify signature.
	CHECK_EQ(1, p256_ecdsa_verify(&pk_x, &pk_y, &h, &sig_r, &sig_s));

  *ctr = ntohl(resp.ctr);

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TestEncodingShortAnyLength(pBleDevice dev)
{
	ReturnValue retval;

	/* write U2F VERSION command to get U2F protocol version */
	unsigned char request[] = { 0x00, 0x03, 0x00, 0x00, 0x00 };
	unsigned char reply[256];
	unsigned int replyLength = sizeof(reply);
	unsigned char replyCmd;

	// short encoding, requesting 255 return bytes.
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_MSG, request, 5, &replyCmd, reply,
			      &replyLength);
	if (!retval)
		return retval;

	CHECK_EQ(FIDO_RESP_SUCCESS, bytes2short(reply, replyLength - 2));

	/* drop reply status code. */
	reply[replyLength - 2] = '\0';

	/* check U2F Protocol version */
	CHECK_EQ((replyLength - 2), 6);
	CHECK_EQ(memcmp(reply, "U2F_V2", 6), 0);

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TestEncodingShortExactLength(pBleDevice dev)
{
	ReturnValue retval;

	/* write U2F VERSION command to get U2F protocol version */
	unsigned char request[] = { 0x00, 0x03, 0x00, 0x00, 0x06 };
	unsigned char reply[256];
	unsigned int replyLength = sizeof(reply);
	unsigned char replyCmd;

	// short encoding, requesting 255 return bytes.
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_MSG, request, 5, &replyCmd, reply,
			      &replyLength);
	if (!retval)
		return retval;

	CHECK_EQ(FIDO_RESP_SUCCESS, bytes2short(reply, replyLength - 2));

	/* drop reply status code. */
	reply[replyLength - 2] = '\0';

	/* check U2F Protocol version */
	CHECK_EQ((replyLength - 2), 6);
	CHECK_EQ(memcmp(reply, "U2F_V2", 6), 0);

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TestEncodingShortWrongLength(pBleDevice dev)
{
	ReturnValue retval;

	/* write U2F VERSION command to get U2F protocol version */
	unsigned char request[] = { 0x00, 0x03, 0x00, 0x00, 0x02 };
	unsigned char reply[256];
	unsigned int replyLength = sizeof(reply);
	unsigned char replyCmd;

	// short encoding, requesting 255 return bytes.
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_MSG, request, 5, &replyCmd, reply,
			      &replyLength);
	if (!retval)
		return retval;

	/* check U2F Protocol version */
	CHECK_EQ(replyLength, 2);
	CHECK_EQ(FIDO_RESP_WRONG_LENGTH, bytes2short(reply, 0));

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TestEncodingLongAnyLength(pBleDevice dev)
{
	ReturnValue retval;

	/* write U2F VERSION command to get U2F protocol version */
	unsigned char request[] = { 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char reply[256];
	unsigned int replyLength = sizeof(reply);
	unsigned char replyCmd;

	// short encoding, requesting 65535 return bytes.
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_MSG, request, 7, &replyCmd, reply,
			      &replyLength);
	if (!retval)
		return retval;

	CHECK_EQ(FIDO_RESP_SUCCESS, bytes2short(reply, replyLength - 2));

	/* drop reply status code. */
	reply[replyLength - 2] = '\0';

	/* check U2F Protocol version */
	CHECK_EQ((replyLength - 2), 6);
	CHECK_EQ(memcmp(reply, "U2F_V2", 6), 0);

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TestEncodingLongExactLength(pBleDevice dev)
{
	ReturnValue retval;

	/* write U2F VERSION command to get U2F protocol version */
	unsigned char request[] = { 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x06 };
	unsigned char reply[256];
	unsigned int replyLength = sizeof(reply);
	unsigned char replyCmd;

	// short encoding, requesting 65535 return bytes.
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_MSG, request, 7, &replyCmd, reply,
			      &replyLength);
	if (!retval)
		return retval;

	CHECK_EQ(FIDO_RESP_SUCCESS, bytes2short(reply, replyLength - 2));

	/* drop reply status code. */
	reply[replyLength - 2] = '\0';

	/* check U2F Protocol version */
	CHECK_EQ((replyLength - 2), 6);
	CHECK_EQ(memcmp(reply, "U2F_V2", 6), 0);

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TestEncodingLongWrongLength(pBleDevice dev)
{
	ReturnValue retval;

	/* write U2F VERSION command to get U2F protocol version */
	unsigned char request[] = { 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x02 };
	unsigned char reply[256];
	unsigned int replyLength = sizeof(reply);
	unsigned char replyCmd;

	// short encoding, requesting 255 return bytes.
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_MSG, request, 7, &replyCmd, reply,
			      &replyLength);
	if (!retval)
		return retval;

	/* check U2F Protocol version */
	CHECK_EQ(replyLength, 2);
	CHECK_EQ(FIDO_RESP_WRONG_LENGTH, bytes2short(reply, 0));

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TestEncodingLongDataAnyLength(pBleDevice dev)
{
	ReturnValue retval;

	U2F_AUTHENTICATE_REQ authReq;
	unsigned char reply[2048];
	unsigned int replyLength = sizeof(reply);
	unsigned char request[256];
	unsigned int requestlen;
	unsigned char replyCmd;

	// pick random challenge and use registered appId.
	for (size_t i = 0; i < sizeof(authReq.nonce); ++i)
		authReq.nonce[i] = rand();
	memcpy(authReq.appId, regReq.appId, sizeof(authReq.appId));
	authReq.keyHandleLen = regRsp.keyHandleLen;
	memcpy(authReq.keyHandle, regRsp.keyHandleCertSig,
	       authReq.keyHandleLen);

	uint64_t t = dev->TimeMs();

	/* prepare register request */
	request[0] = 0x00;
	request[1] = U2F_INS_AUTHENTICATE;
	request[2] = U2F_AUTH_ENFORCE;
	request[3] = 0x00;
	request[4] = 0x00;
	request[5] = 0x00;
	request[6] = U2F_NONCE_SIZE + U2F_APPID_SIZE + 1 + authReq.keyHandleLen;
	memcpy(request + 7, reinterpret_cast < char *>(&authReq), request[6]);
	requestlen = 7 + request[6];
	request[requestlen++] = 0x00;
	request[requestlen++] = 0x00;

	/* write command */
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_MSG, request, requestlen, &replyCmd,
			      reply, &replyLength);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	CHECK_EQ(replyCmd, FIDO_BLE_CMD_MSG);
	CHECK_EQ(FIDO_RESP_SUCCESS, bytes2short(reply, replyLength - 2));
	CHECK_NE(replyLength, 2);
	CHECK_LE(replyLength - 2, sizeof(U2F_AUTHENTICATE_RESP));

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TestEncodingLongDataExactLength(pBleDevice dev)
{
	ReturnValue retval;

	U2F_AUTHENTICATE_REQ authReq;
	unsigned char reply[2048];
	unsigned int replyLength = sizeof(reply);
	unsigned char request[256];
	unsigned int requestlen;
	unsigned char replyCmd;

	// pick random challenge and use registered appId.
	for (size_t i = 0; i < sizeof(authReq.nonce); ++i)
		authReq.nonce[i] = rand();
	memcpy(authReq.appId, regReq.appId, sizeof(authReq.appId));
	authReq.keyHandleLen = regRsp.keyHandleLen;
	memcpy(authReq.keyHandle, regRsp.keyHandleCertSig,
	       authReq.keyHandleLen);

	uint64_t t = dev->TimeMs();

	/* prepare register request */
	request[0] = 0x00;
	request[1] = U2F_INS_AUTHENTICATE;
	request[2] = U2F_AUTH_ENFORCE;
	request[3] = 0x00;
	request[4] = 0x00;
	request[5] = 0x00;
	request[6] = U2F_NONCE_SIZE + U2F_APPID_SIZE + 1 + authReq.keyHandleLen;
	memcpy(request + 7, reinterpret_cast < char *>(&authReq), request[6]);
	requestlen = 7 + request[6];
	request[requestlen++] = 0x00;
	/* 1 byte user presence + 4 bytes counter + upto (6 + 33 + 33) bytes signature */
	request[requestlen++] = 0x01 + 0x04 + 0x48;

	/* write command */
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_MSG, request, requestlen, &replyCmd,
			      reply, &replyLength);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	CHECK_EQ(replyCmd, FIDO_BLE_CMD_MSG);
	CHECK_EQ(FIDO_RESP_SUCCESS, bytes2short(reply, replyLength - 2));
	CHECK_NE(replyLength, 2);
	CHECK_LE(replyLength - 2, sizeof(U2F_AUTHENTICATE_RESP));

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TestEncodingLongDataWrongLength(pBleDevice dev)
{
	ReturnValue retval;

	U2F_AUTHENTICATE_REQ authReq;
	unsigned char reply[2048];
	unsigned int replyLength = sizeof(reply);
	unsigned char request[256];
	unsigned int requestlen;
	unsigned char replyCmd;

	// pick random challenge and use registered appId.
	for (size_t i = 0; i < sizeof(authReq.nonce); ++i)
		authReq.nonce[i] = rand();
	memcpy(authReq.appId, regReq.appId, sizeof(authReq.appId));
	authReq.keyHandleLen = regRsp.keyHandleLen;
	memcpy(authReq.keyHandle, regRsp.keyHandleCertSig,
	       authReq.keyHandleLen);

	uint64_t t = dev->TimeMs();

	/* prepare register request */
	request[0] = 0x00;
	request[1] = U2F_INS_AUTHENTICATE;
	request[2] = U2F_AUTH_ENFORCE;
	request[3] = 0x00;
	request[4] = 0x00;
	request[5] = 0x00;
	request[6] = U2F_NONCE_SIZE + U2F_APPID_SIZE + 1 + authReq.keyHandleLen;
	memcpy(request + 7, reinterpret_cast < char *>(&authReq), request[6]);
	requestlen = 7 + request[6];
	request[requestlen++] = 0x00;
	request[requestlen++] = 0x08;	/* fixed at 8 bytes, which is too short */

	/* write command */
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_MSG, request, requestlen, &replyCmd,
			      reply, &replyLength);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	/* check U2F Protocol version */
	CHECK_EQ(replyLength, 2);
	CHECK_EQ(FIDO_RESP_WRONG_LENGTH, bytes2short(reply, 0));

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}
