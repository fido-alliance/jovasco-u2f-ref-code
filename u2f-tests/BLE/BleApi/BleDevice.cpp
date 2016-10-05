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

#include "BleDevice.h"

#include <iostream>

#include <string.h>
#include "fido_ble.h"

static std::string bytes2ascii(const unsigned char *ptr, int len)
{
	static const char *convert = "0123456789ABCDEF";
	std::string r;
	int i;

	for (i = 0; i < len; i++) {
		const unsigned char c = ptr[i];

		r += convert[(c >> 4) & 0x0F];
		r += convert[(c) & 0x0F];
	}

	return r;
}

 BleDevice::BleDevice(BleApiConfiguration &configuration) :
mCommandInProgress(false), mTimeout(0), mConfiguration(configuration), mSupportsVersion_1_0(false), mSupportsVersion_1_1(false)
{
}

BleDevice::~BleDevice(void)
{
	mEventHandlerList.clear();
}

ReturnValue BleDevice::Verify()
{
  // don't throw an exception if not implemetned.
  return ReturnValue::BLEAPI_ERROR_NOT_IMPLEMENTED;
}

ReturnValue BleDevice::ControlPointWrite(unsigned char *buffer,
					 unsigned int bufferLength)
{
	throw std::exception("Not Implemented.");
}

ReturnValue BleDevice::ControlPointLengthRead(unsigned int *length)
{
	throw std::exception("Not Implemented.");
}

ReturnValue BleDevice::U2FVersionRead(unsigned char *buffer,
				      unsigned int *bufferLength)
{
	throw std::exception("Not Implemented.");
}

ReturnValue BleDevice::U2FVersionBitfieldRead(unsigned char * buffer, unsigned int * bufferLength)
{
  throw std::exception("Not Implemented.");
}

ReturnValue BleDevice::U2FVersionBitfieldWrite(unsigned char * buffer, unsigned int * bufferLength)
{
  throw std::exception("Not Implemented.");
}

ReturnValue BleDevice::Sleep(unsigned int miliseconds)
{
	throw std::exception("Not Implemented.");
}

ReturnValue BleDevice::RegisterNotifications(pEventHandler eventHandler)
{
	mEventHandlerList.push_back(eventHandler);

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

uint64_t BleDevice::TimeMs()
{
	throw std::exception("Not Implemented.");
}

ReturnValue BleDevice::SetTimeout(uint64_t timeoutms)
{
	mTimeout = timeoutms;
	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

// device Identification
std::string BleDevice::Identifier()
{
	throw std::exception("Not Implemented.");
}

bool BleDevice::SupportsVersion(U2FVersion version)
{
  switch (version) {
  case U2FVersion::V1_0:
    return mSupportsVersion_1_0;
  case U2FVersion::V1_1:
    return mSupportsVersion_1_1;
  }
  return false;
}

bool BleDevice::SelectVersion(U2FVersion version, bool force)
{
  throw std::exception("Not Implemented.");
}

bool BleDevice::IsConnected()
{
  throw std::exception("Not Implemented.");
}

bool BleDevice::IsPaired()
{
  throw std::exception("Not Implemented.");
}

bool BleDevice::IsAdvertising()
{
  throw std::exception("Not Implemented.");
}

bool BleDevice::IsAuthenticated()
{
  throw std::exception("Not Implemented.");
}

ReturnValue BleDevice::Unpair()
{
  throw std::exception("Not Implemented.");
}

ReturnValue BleDevice::Pair()
{
  throw std::exception("Not Implemented.");
}

void BleDevice::Report()
{
  throw std::exception("Not Implemented.");
}

ReturnValue BleDevice::WaitForDevice(BleAdvertisement **, BleAdvertisement **)
{
  ReturnValue retval;
  unsigned char version[128];
  unsigned int len = sizeof(version);

  do {
    printf("\n%s", "Turn on device and hit enter..");
    getchar();
    printf("\n");

    /* check for U2F Interface version */
    retval = U2FVersionRead(version, &len);
  } while (retval != ReturnValue::BLEAPI_ERROR_SUCCESS);

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDevice::WaitForAdvertisementStop()
{
  throw std::exception("Not Implemented.");
}

ReturnValue BleDevice::WaitForAdvertisement(bool withPairingMode)
{
  throw std::exception("Not Implemented.");
}

void BleDevice::Lock()
{
	throw std::exception("Not Implemented.");
}

void BleDevice::UnLock()
{
	throw std::exception("Not Implemented.");
}

/* send a full command */
ReturnValue BleDevice::CommandWrite(unsigned char cmd, unsigned char *buffer,
				    unsigned int bufferLength,
				    unsigned char *replyCmd,
				    unsigned char *reply,
				    unsigned int *replyLength)
{
	ReturnValue retval = ReturnValue::BLEAPI_ERROR_SUCCESS;
	unsigned int controlPointLength, i, sequence, offset, l;
	uint64_t start;

	// start parsing events
	Lock();
	{
		mCommandInProgress = true;
		mReplyBuffer = reply;
		mReplyBufferLength = *replyLength;
		mReceived = 0;
		mReplyRetval = ReturnValue::BLEAPI_ERROR_SUCCESS;
		mReplyCmd = replyCmd;
		mReplyErrorMessage = NULL;
	}
	UnLock();

	// fetch the controlpoint length
	retval = ControlPointLengthRead(&controlPointLength);
	if (retval != ReturnValue::BLEAPI_ERROR_SUCCESS)
		return retval;

	// get a buffer
	unsigned char *segment = new unsigned char[controlPointLength];

	// start segmenting
	sequence = 0;

	start = TimeMs();

	// initialize first packet
	segment[0] = cmd;
	segment[1] = (bufferLength >> 8) & 0xFF;
	segment[2] = (bufferLength) & 0xFF;
	offset = 3;

	i = 0;
	do {
		// stop writing if we received an error.
		Lock();
		if (!mCommandInProgress) {
			UnLock();
			break;
		}
		UnLock();

		// length to send write this time.
		l = (controlPointLength - offset);
		if (l > (bufferLength - i))
			l = (bufferLength - i);

		// fill segment data
		memcpy(segment + offset, buffer + i, l);

		// write to ControlPoint
		retval = ControlPointWrite(segment, l + offset);
		if (retval != ReturnValue::BLEAPI_ERROR_SUCCESS)
			break;

		// header for next packet
		segment[0] = sequence++;
		offset = 1;
		i += l;
	} while (i < bufferLength);

	delete segment;

	if (retval != ReturnValue::BLEAPI_ERROR_SUCCESS)
		return retval;

	// wait for reply
	Lock();
	while (mCommandInProgress
	       && ((mTimeout == 0) || ((start + mTimeout) > TimeMs()))) {
		UnLock();
		Sleep(10);
		Lock();
	}
	UnLock();

	// in case of timeout
	if (mCommandInProgress) {
		mCommandInProgress = false;
		return ReturnValue::BLEAPI_ERROR_TIMEOUT;
	}
	// success.
	*replyLength = mReceived;

	if (!mReplyRetval)
		throw(std::runtime_error(mReplyErrorMessage));

	return mReplyRetval;
}

//
//  Must be called under lock
//
void BleDevice::EventHandler(BleDevice::FIDOEventType type,
			     unsigned char *buffer, unsigned int bufferLength)
{
	if (!mCommandInProgress) {
		std::vector < pEventHandler >::iterator i;

		for (i = mEventHandlerList.begin();
		     i != mEventHandlerList.end(); i++)
			(*i) (type, buffer, bufferLength);

		goto leave;
	}

	unsigned int l = 0;
	if (mReceived == 0) {
		//
		//   New transfer
		//
		// first packet of reply needs init flag set
		if ((buffer[0] & TYPE_MASK) != TYPE_INIT) {
			mReplyRetval = ReturnValue::BLEAPI_ERROR_BAD_REPLY;
			mCommandInProgress = false;
			mReplyErrorMessage = "First packet is not TYPE_INIT";
			goto leave;
		}
		// ignore keep-alive for now.
		if (buffer[0] == FIDO_BLE_CMD_KEEPALIVE)
			goto leave;

		// extract header information
		mExpected = ((short)(buffer[1] << 8)) | (buffer[2] & 0xFF);
		if (mReplyCmd)
			*mReplyCmd = buffer[0];

		// check reported length
		if (mExpected > mReplyBufferLength) {
			mReplyRetval = ReturnValue::BLEAPI_ERROR_BUFFER_TOO_SMALL;
			mCommandInProgress = false;
			mReplyErrorMessage = "More bytes sent than expected.";
			goto leave;
		}
		// data to copy.
		l = bufferLength - 3;

		mSequence = 0;
	} else {
		// ignore keep-alive for now.
		if (buffer[0] == FIDO_BLE_CMD_KEEPALIVE) {
			mReplyRetval = ReturnValue::BLEAPI_ERROR_BAD_REPLY;
			mCommandInProgress = false;
			mReplyErrorMessage = "Keep-alive during reply.";
			goto leave;
		}
		// verify init flag absent
		if ((buffer[0] & TYPE_MASK) != TYPE_CONT) {
			mReplyRetval = ReturnValue::BLEAPI_ERROR_BAD_REPLY;
			mCommandInProgress = false;
			mReplyErrorMessage = "Follow up packet not TYPE_CONT.";
			goto leave;
		}
		// verify sequence number
		if (buffer[0] != mSequence++) {
			mReplyRetval = ReturnValue::BLEAPI_ERROR_BAD_SEQUENCE;
			mCommandInProgress = false;
			mReplyErrorMessage = "Bad sequence.";
			goto leave;
		}
		// data to copy
		l = bufferLength - 1;
	}

	// common part

	// verify the length of the buffer returned.
	if (l > (mExpected - mReceived)) {
		mReplyRetval = ReturnValue::BLEAPI_ERROR_REPLY_TOO_LONG;
		mCommandInProgress = false;
		mReplyErrorMessage = "Reply is too long.";
		goto leave;
	}
	// copy data
	if (mReplyBuffer)
		memcpy(mReplyBuffer + mReceived, buffer + bufferLength - l, l);

	// count received data
	mReceived += l;

	// complete?
	if (mReceived == mExpected) {
		mReplyRetval = ReturnValue::BLEAPI_ERROR_SUCCESS;
		mCommandInProgress = false;
	}

 leave:
	return;
}
