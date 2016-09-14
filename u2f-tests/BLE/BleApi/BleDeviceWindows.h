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

#ifndef _BLEAPI_BLEDEVICEWINDOWS_H_
#define _BLEAPI_BLEDEVICEWINDOWS_H_

#include <windows.h>
#include <initguid.h>
#include <guiddef.h>
#include <setupapi.h>
#include <string>
#include <vector>
#include <cfgmgr32.h>

#include <BthDef.h>
#pragma warning( disable : 4068 )
#include <BthLEDef.h>
#pragma warning( default : 4068 )
#include <BluetoothLEApis.h>
#include <BluetoothAPIs.h>

#include "BleApi.h"
#include "BleDevice.h"
#include "BleApiError.h"

class BleDeviceWindows : public BleDevice {
 public:
	BleDeviceWindows(pBleApi pBleApi, std::string deviceInstanceId,
			 HANDLE deviceHandle, HANDLE serviceHandle,
			 bool encrypt = true, bool logging = false);
	~BleDeviceWindows();

	bool hasPath(std::string path);

 public:
	 virtual ReturnValue ControlPointWrite(unsigned char *buffer,
					       unsigned int bufferLength);
	virtual ReturnValue ControlPointLengthRead(unsigned int *length);
	virtual ReturnValue U2FVersionRead(unsigned char *buffer,
					   unsigned int *bufferLength);
	virtual ReturnValue RegisterNotifications(pEventHandler eventHandler);

	VOID OnBluetoothGattEventCallback(_In_ BTH_LE_GATT_EVENT_TYPE EventType,
					  _In_ PVOID EventOutParameter);

	virtual ReturnValue Sleep(unsigned int miliseconds);
	virtual uint64_t TimeMs();

	// device Identification
	virtual std::string Identifier();

 protected:
	 virtual void Lock();
	virtual void UnLock();

 protected:
	std::string mDeviceInstanceId;
	bool mEventHandleValid;
	HANDLE mDeviceHandle;
	HANDLE mEventHandle;
	HANDLE mServiceHandle;
	HANDLE mMutex;
	BTH_LE_GATT_SERVICE mService;
	BTH_LE_GATT_CHARACTERISTIC mCharacteristicControlPointLength;
	BTH_LE_GATT_CHARACTERISTIC mCharacteristicControlPoint;
	BTH_LE_GATT_CHARACTERISTIC mCharacteristicStatus;
	BTH_LE_GATT_CHARACTERISTIC mCharacteristicVersion;

	BTH_LE_GATT_DESCRIPTOR mDescriptorCCC;
};

#endif				/* _BLEAPI_BLEDEVICEWINDOWS_H_ */
