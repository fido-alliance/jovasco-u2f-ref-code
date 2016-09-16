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

#ifndef _BLEAPI_FIDODEVICE_H_
#define _BLEAPI_FIDODEVICE_H_

#include <vector>

#include <stdint.h>

#include "BleApiTypes.h"
#include "BleApiError.h"

typedef class BleDevice {
 public:
	typedef enum {
		EVENT_REPLY = 1,
		EVENT_FRAGMENT = 2,
	} FIDOEventType;

	typedef void (*pEventHandler) (FIDOEventType type,
				       unsigned char *buffer,
				       unsigned int bufferLength);

 protected:
	 BleDevice(BleApiConfiguration &configuration);

 public:
	~BleDevice(void);

 public:
	// raw FIDO access
	 virtual ReturnValue ControlPointWrite(unsigned char *buffer,
					       unsigned int bufferLength);
	virtual ReturnValue ControlPointLengthRead(unsigned int *length);
	virtual ReturnValue U2FVersionRead(unsigned char *buffer,
					   unsigned int *bufferLength);
  virtual ReturnValue U2FVersionBitfieldRead(unsigned char *buffer,
             unsigned int *bufferLength);
  virtual ReturnValue U2FVersionBitfieldWrite(unsigned char *buffer,
    unsigned int *bufferLength);
  virtual ReturnValue RegisterNotifications(pEventHandler eventHandler);

	// send a full command 
	virtual ReturnValue CommandWrite(unsigned char cmd,
					 unsigned char *buffer,
					 unsigned int bufferLength,
					 unsigned char *replyCmd,
					 unsigned char *reply,
					 unsigned int *replyLength);

	// utilities
	virtual ReturnValue SetTimeout(uint64_t timeoutms);
	virtual ReturnValue Sleep(unsigned int miliseconds);
	virtual uint64_t TimeMs();

	// device Identification
	virtual std::string Identifier();

  // version management
  virtual bool SupportsVersion(U2FVersion version);
  virtual bool SelectVersion(U2FVersion version, bool force = false);

 protected:
	// routes events and does reassembly for CommandWrite 
	 virtual void EventHandler(FIDOEventType type, unsigned char *buffer,
				   unsigned int bufferLength);

	virtual void Lock();
	virtual void UnLock();

 private:
	// used during CommandWrite
	 bool mCommandInProgress;
	// used during reassembly of reply
	unsigned char *mReplyBuffer;
	unsigned int mReplyBufferLength;
	unsigned char *mReplyCmd;
	unsigned int mReceived;
	unsigned int mExpected;
	unsigned char mSequence;
	uint64_t mTimeout;
	ReturnValue mReplyRetval;
	char *mReplyErrorMessage;

	std::vector < pEventHandler > mEventHandlerList;

 protected:
	// do we need to do encryption
  BleApiConfiguration mConfiguration;

  bool mSupportsVersion_1_0;
  bool mSupportsVersion_1_1;
} *pBleDevice;

#endif				/* _BLEAPI_FIDODEVICE_H_ */
