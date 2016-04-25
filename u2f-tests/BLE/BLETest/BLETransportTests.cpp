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

#include "BLETransportTests.h"

#include "fido_ble.h"
#include "ble_util.h"

bool eventDone = true;

#define REPLY_BUFFER_LENGTH  	512
unsigned char fragmentReplyBuffer[REPLY_BUFFER_LENGTH];
unsigned int fragmentReplyBufferLength;

ReturnValue WaitForEvent(pBleDevice dev, unsigned int timeout)
{
	uint64_t deadline = dev->TimeMs() + timeout;

	while (!eventDone && ((timeout == 0) || (deadline > dev->TimeMs()))) {
		dev->Sleep(100);
	}

	if (!eventDone)
		return BLEAPI_ERROR_TIMEOUT;

	return BLEAPI_ERROR_SUCCESS;
}

void BleApiTest_TransportEventHandler(BleDevice::FIDOEventType type,
				      unsigned char *buffer,
				      unsigned int bufferLength)
{
	// are we waiting for input?
	if (eventDone)
		return;

	// ignore keep-alives here.     
	if (buffer[0] == FIDO_BLE_CMD_KEEPALIVE)
		return;

	memcpy(fragmentReplyBuffer, buffer, bufferLength);
	fragmentReplyBufferLength = bufferLength;

	eventDone = true;
}

ReturnValue BleApiTest_TransportPing(pBleDevice dev)
{
	ReturnValue retval;
	float sent, received;

	unsigned int i;
	unsigned char request[8];
	unsigned int requestLength = 8;
	unsigned char reply[8];
	unsigned int replyLength = 8;
	unsigned char replyCmd = 0;

	for (i = 0; i < requestLength; i++)
		request[i] = (rand() & 0xFF);

	sent = (float)dev->TimeMs();
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_PING, request, requestLength,
			      &replyCmd, reply, &replyLength);
	CHECK_EQ(retval, BLEAPI_ERROR_SUCCESS);

	received = (float)dev->TimeMs();
	INFO << "Sent " << requestLength << " bytes in " << (received -
							     sent) /
	    1000.0 << " s.";

	CHECK_EQ(replyCmd, FIDO_BLE_CMD_PING);
	CHECK_EQ(replyLength, requestLength);
	CHECK_EQ(memcmp(request, reply, requestLength), 0);

	return BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TransportUnknown(pBleDevice dev, unsigned char cmd)
{
	ReturnValue retval;
	float sent, received;

	unsigned int i;
	unsigned char request[8];
	unsigned int requestLength = 0;
	unsigned char reply[8];
	unsigned int replyLength = 8;
	unsigned char replyCmd = 0;

	// always set INIT bit
	cmd |= 0x80;

	for (i = 0; i < sizeof(request); i++)
		request[i] = (rand() & 0xFF);

	sent = (float)dev->TimeMs();
	retval =
	    dev->CommandWrite(cmd, request, requestLength, &replyCmd, reply,
			      &replyLength);
	CHECK_EQ(retval, BLEAPI_ERROR_SUCCESS);

	received = (float)dev->TimeMs();
	INFO << "Sent cmd 0x" << std::hex << (int)cmd << std::dec << " with " <<
	    requestLength << " bytes in " << (received - sent) / 1000.0 << "s.";

	CHECK_EQ(replyCmd, FIDO_BLE_CMD_ERROR);
	WARN_EQ(replyLength, 1);
	WARN_EQ(reply[0], ERR_INVALID_CMD);

	return BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TransportLongPing(pBleDevice dev)
{
	ReturnValue retval;
	float sent, received;

	unsigned int i;
	unsigned char request[128];
	unsigned int requestLength = 128;
	unsigned char reply[128];
	unsigned int replyLength = 128;
	unsigned char replyCmd = 0;

	for (i = 0; i < requestLength; i++)
		request[i] = (rand() & 0xFF);

	sent = (float)dev->TimeMs();
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_PING, request, requestLength,
			      &replyCmd, reply, &replyLength);
	CHECK_EQ(retval, BLEAPI_ERROR_SUCCESS);

	received = (float)dev->TimeMs();
	INFO << "Sent " << requestLength << " bytes in " << (received -
							     sent) /
	    1000.0 << "s.";

	return BLEAPI_ERROR_SUCCESS;
}

#define LIMITS_MAXLENGTH		((1 << 16))
ReturnValue BleApiTest_TransportLimits(pBleDevice dev)
{
	ReturnValue retval;
	float sent, received;

	unsigned int i, l;
	unsigned char request[LIMITS_MAXLENGTH];
	unsigned int requestLength;
	unsigned char reply[LIMITS_MAXLENGTH];
	unsigned int replyLength;
	unsigned char replyCmd = 0;

	for (i = 0; i < LIMITS_MAXLENGTH; i++)
		request[i] = (rand() & 0xFF);

	l = 256;
	do {
		INFO << "Testing with " << l << " bytes.";
		requestLength = l;
		replyLength = l;

		sent = (float)dev->TimeMs();
		retval =
		    dev->CommandWrite(FIDO_BLE_CMD_PING, request, requestLength,
				      &replyCmd, reply, &replyLength);
		CHECK_EQ(retval, BLEAPI_ERROR_SUCCESS);

		received = (float)dev->TimeMs();

		if (replyCmd == FIDO_BLE_CMD_PING) {
			CHECK_EQ(replyLength, l);
			CHECK_EQ(memcmp(request, reply, l), 0);
			INFO << "  Sent " << requestLength << " bytes in " <<
			    (received - sent) / 1000.0 << "s.";
		} else if (replyCmd == FIDO_BLE_CMD_ERROR) {
			CHECK_EQ(replyLength, 1);
			WARN_EQ(reply[0], ERR_INVALID_LEN);
			INFO << "  Limit is smaller than " << requestLength <<
			    " bytes.";
		} else {
			CHECK_EQ(((replyCmd == FIDO_BLE_CMD_ERROR)
				  || (replyCmd == FIDO_BLE_CMD_PING)), 1);
		}

		l <<= 1;
	}
	while (replyCmd == FIDO_BLE_CMD_PING);

	dev->Sleep(1000);

	return BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TransportNotCont(pBleDevice dev)
{
	ReturnValue retval;

	unsigned int cpl, l;
	unsigned char request[8192] = { FIDO_BLE_CMD_MSG, 0x00, 0x20, };

	// get control point length
	retval = dev->ControlPointLengthRead(&cpl);
	CHECK_EQ(retval, BLEAPI_ERROR_SUCCESS);

	eventDone = false;

	CHECK_LE(cpl, 8192);

	// write needs to be longer than cpl
	l = cpl + 1;
	request[1] = (l >> 8) & 0xFF;
	request[2] = (l) & 0xFF;

	// send first INIT frame
	retval = dev->ControlPointWrite(request, cpl);
	CHECK_EQ(retval, BLEAPI_ERROR_SUCCESS);

	// no reply expected

	// send INIT frame again while CONT is expected
	retval = dev->ControlPointWrite(request, cpl);
	CHECK_EQ(retval, BLEAPI_ERROR_SUCCESS);

	retval = WaitForEvent(dev, 10000);
	CHECK_EQ(retval, BLEAPI_ERROR_SUCCESS);

	// check if this is error reply
	CHECK_EQ(fragmentReplyBuffer[0], FIDO_BLE_CMD_ERROR);

	// check total reply length
	WARN_EQ(fragmentReplyBufferLength, 3 /* header */  + 1 /* data */ );
	// check 1 data byte length
	WARN_EQ((((short)fragmentReplyBuffer[1]) << 8 | fragmentReplyBuffer[2]),
		1);
	// check invalid seq error
	WARN_EQ(fragmentReplyBuffer[3], ERR_INVALID_SEQ);

	return BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TransportBadSequence(pBleDevice dev)
{
	ReturnValue retval;

	unsigned int cpl;
	unsigned char request[8192 * 2] = { FIDO_BLE_CMD_MSG, };

	// get control point length
	retval = dev->ControlPointLengthRead(&cpl);
	CHECK_EQ(retval, BLEAPI_ERROR_SUCCESS);

	eventDone = false;

	CHECK_LE(cpl, 8192);

	// build correct request
	request[0] = FIDO_BLE_CMD_MSG;
	request[1] = (cpl >> 8) & 0xFF;
	request[2] = cpl & 0xFF;

	// wrong sequence, should be 0 
	request[cpl] = 0x01;

	// send first INIT frame
	retval = dev->ControlPointWrite(request, cpl);
	CHECK_EQ(retval, BLEAPI_ERROR_SUCCESS);

	// no reply expected

	// send CONT frame with bad sequence number
	retval = dev->ControlPointWrite(request + cpl, cpl);
	CHECK_EQ(retval, BLEAPI_ERROR_SUCCESS);

	// wait upto 10 seconds for a reply.
	retval = WaitForEvent(dev, 10000);
	CHECK_EQ(retval, BLEAPI_ERROR_SUCCESS);

	// check if this is error reply
	CHECK_EQ(fragmentReplyBuffer[0], FIDO_BLE_CMD_ERROR);

	// should have length of 3 header + 1 data byte
	WARN_EQ(fragmentReplyBufferLength, 3 /* header */  + 1 /* data */ );
	// check 1 data byte length
	WARN_EQ((((short)fragmentReplyBuffer[1]) << 8 | fragmentReplyBuffer[2]),
		1);
	// check invalid seq error
	WARN_EQ(fragmentReplyBuffer[3], ERR_INVALID_SEQ);

	return BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TransportContFirst(pBleDevice dev)
{
	ReturnValue retval;

	unsigned int cpl;
	unsigned char request[1024] = { FIDO_BLE_CMD_MSG, };

	// get control point length
	retval = dev->ControlPointLengthRead(&cpl);
	CHECK_EQ(retval, BLEAPI_ERROR_SUCCESS);

	eventDone = false;

	// build correct request
	request[0] = 0;

	// send CONT frame
	retval = dev->ControlPointWrite(request, cpl);
	CHECK_EQ(retval, BLEAPI_ERROR_SUCCESS);

	// wait upto 10 seconds for a reply.
	retval = WaitForEvent(dev, 10000);
	CHECK_EQ(retval, BLEAPI_ERROR_SUCCESS);

	// check if this is error reply
	CHECK_EQ(fragmentReplyBuffer[0], FIDO_BLE_CMD_ERROR);

	// should have length of 3 header + 1 data byte
	WARN_EQ(fragmentReplyBufferLength, 3 /* header */  + 1 /* data */ );
	// check 1 data byte length
	WARN_EQ((((short)fragmentReplyBuffer[1]) << 8 | fragmentReplyBuffer[2]),
		1);

	// check invalid seq error
	WARN_EQ(fragmentReplyBuffer[3], ERR_INVALID_SEQ);

	return BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TransportTooLong(pBleDevice dev)
{
	ReturnValue retval;

	unsigned int cpl;
	unsigned char request[1024] = { FIDO_BLE_CMD_PING, 0x00, 0x01, };

	// get control point length
	retval = dev->ControlPointLengthRead(&cpl);
	CHECK_EQ(retval, BLEAPI_ERROR_SUCCESS);

	eventDone = false;

	// send INIT frame with too much data
	retval = dev->ControlPointWrite(request, cpl);
	CHECK_EQ(retval, BLEAPI_ERROR_SUCCESS);

	// wait upto 10 seconds for a reply.
	retval = WaitForEvent(dev, 10000);
	CHECK_EQ(retval, BLEAPI_ERROR_SUCCESS);

	// check if this is error reply
	CHECK_EQ(fragmentReplyBuffer[0], FIDO_BLE_CMD_ERROR);

	// should have length of 3 header + 1 data byte
	WARN_EQ(fragmentReplyBufferLength, 3 /* header */  + 1 /* data */ );
	// check 1 data byte length
	WARN_EQ((((short)fragmentReplyBuffer[1]) << 8 | fragmentReplyBuffer[2]),
		1);
	// check invalid seq error
	WARN_EQ(fragmentReplyBuffer[3], ERR_INVALID_LEN);

	return BLEAPI_ERROR_SUCCESS;
}
