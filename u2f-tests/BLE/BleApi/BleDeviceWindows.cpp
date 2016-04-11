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

#include <windows.h>

#include <iostream>
#include <stdexcept>

#include "fido_ble.h"
#include "BleDeviceWindows.h"
#include "BleApiError.h"

#include <comdef.h>

DEFINE_GUID(GUID_BLUETOOTHLE_FIDO_CONTROLPOINT, 0xF1D0FFF1, 0xDEAA, 0xECEE,
	    0xB4, 0x2F, 0xC9, 0xBA, 0x7E, 0xD6, 0x23, 0xBB);
DEFINE_GUID(GUID_BLUETOOTHLE_FIDO_STATUS, 0xF1D0FFF2, 0xDEAA, 0xECEE, 0xB4,
	    0x2F, 0xC9, 0xBA, 0x7E, 0xD6, 0x23, 0xBB);
DEFINE_GUID(GUID_BLUETOOTHLE_FIDO_CTRLPT_LEN, 0xF1D0FFF3, 0xDEAA, 0xECEE, 0xB4,
	    0x2F, 0xC9, 0xBA, 0x7E, 0xD6, 0x23, 0xBB);
#define GUID_BLUETOOTHLE_FIDO_VERSION	0x2A28

#define HRESULT_RUNTIME_EXCEPTION(x)		hresult_exception(__FILE__, __LINE__, x);
#define STRING_RUNTIME_EXCEPTION(x)		std::runtime_error( __FILE__ + std::to_string(__LINE__) + x)

inline std::runtime_error hresult_exception(std::string file, int line,
					    HRESULT result)
{
	_com_error err(result, NULL, false);

	std::string m;
	m.append(file);
	m.append(":");
	m.append(std::to_string(line));
	m.append(" ");
	m.append((const char *)err.ErrorMessage());
	return std::runtime_error(m);
}

VOID OnBluetoothGattEventCallback(_In_ BTH_LE_GATT_EVENT_TYPE EventType,
				  _In_ PVOID EventOutParameter,
				  _In_opt_ PVOID Context)
{
	BleDeviceWindows *dev = (BleDeviceWindows *) Context;

	dev->OnBluetoothGattEventCallback(EventType, EventOutParameter);
}

VOID BleDeviceWindows::OnBluetoothGattEventCallback(_In_ BTH_LE_GATT_EVENT_TYPE
						    EventType,
						    _In_ PVOID
						    EventOutParameter)
{
	switch (EventType) {
	case BTH_LE_GATT_EVENT_TYPE::CharacteristicValueChangedEvent:
		{
			PBLUETOOTH_GATT_VALUE_CHANGED_EVENT event =
			    (PBLUETOOTH_GATT_VALUE_CHANGED_EVENT)
			    EventOutParameter;

			EventHandler(BleDevice::FIDOEventType::EVENT_FRAGMENT,
				     event->CharacteristicValue->Data,
				     event->CharacteristicValue->DataSize);
		}
	default:
		break;
	}
}

 BleDeviceWindows::BleDeviceWindows(pBleApi pBleApi, std::string deviceInstanceId, HANDLE deviceHandle, HANDLE serviceHandle, bool encrypt):
BleDevice(encrypt), mDeviceInstanceId(deviceInstanceId), mDeviceHandle(deviceHandle),	// take ownership
    mServiceHandle(serviceHandle)
    // take ownership
{
	int i;
	HRESULT hResult;
	BTH_LE_GATT_SERVICE disService;
	USHORT serviceCount, serviceBufferCount;
	USHORT characteristicsBufferCount, characteristicsCount;
	USHORT descriptorBufferCount, descriptorCount;
	PBTH_LE_GATT_SERVICE services;
	PBTH_LE_GATT_CHARACTERISTIC characteristics;
	PBTH_LE_GATT_DESCRIPTOR descriptors;

	hResult =
	    BluetoothGATTGetServices(mDeviceHandle, 0, NULL,
				     &serviceBufferCount,
				     BLUETOOTH_GATT_FLAG_NONE);
	if (hResult != HRESULT_FROM_WIN32(ERROR_MORE_DATA))
		throw HRESULT_RUNTIME_EXCEPTION(hResult);

	//
	// Find the required services.
	//
	services =
	    (PBTH_LE_GATT_SERVICE) malloc(sizeof(BTH_LE_GATT_SERVICE) *
					  serviceBufferCount);
	if (!services)
		throw HRESULT_RUNTIME_EXCEPTION(E_OUTOFMEMORY);

	hResult =
	    BluetoothGATTGetServices(mDeviceHandle, serviceBufferCount,
				     services, &serviceCount,
				     BLUETOOTH_GATT_FLAG_NONE);
	if (FAILED(hResult)) {
		free(services);
		throw HRESULT_RUNTIME_EXCEPTION(hResult);
	}

	for (i = 0; i < serviceCount; i++) {
		if (!services[i].ServiceUuid.IsShortUuid)
			continue;

		if (services[i].ServiceUuid.Value.ShortUuid !=
		    FIDO_SERVICE_SHORTUUID)
			continue;

		mService = services[i];
		break;
	}

	// find the Device Information Service
	for (i = 0; i < serviceCount; i++) {
		if (!services[i].ServiceUuid.IsShortUuid)
			continue;

		if (services[i].ServiceUuid.Value.ShortUuid != 0x180A)
			continue;
		disService = services[i];
		break;
	};
	if (i == serviceCount) {
		free(services);
		throw STRING_RUNTIME_EXCEPTION("Can't find FIDO Service.");
	}
	// clean up memory
	free(services);

	//
	//  check the DIS
	//
	hResult =
	    BluetoothGATTGetCharacteristics(mDeviceHandle, &disService, 0, NULL,
					    &characteristicsBufferCount,
					    BLUETOOTH_GATT_FLAG_NONE);
	if (hResult != HRESULT_FROM_WIN32(ERROR_MORE_DATA))
		throw HRESULT_RUNTIME_EXCEPTION(hResult);

	characteristics = (PBTH_LE_GATT_CHARACTERISTIC)
	    malloc(sizeof(BTH_LE_GATT_CHARACTERISTIC) *
		   characteristicsBufferCount);
	if (!characteristics)
		throw HRESULT_RUNTIME_EXCEPTION(E_OUTOFMEMORY);

	hResult =
	    BluetoothGATTGetCharacteristics(mDeviceHandle, &disService,
					    characteristicsBufferCount,
					    characteristics,
					    &characteristicsCount,
					    BLUETOOTH_GATT_FLAG_NONE);
	if (FAILED(hResult)) {
		free(characteristics);
		throw HRESULT_RUNTIME_EXCEPTION(hResult);
	}

	bool foundManufactorersNameString = false, foundModelNumberString =
	    false, foundFirmwareRevisionString = false;
	for (i = 0; i < characteristicsCount; i++) {
		if (!characteristics[i].CharacteristicUuid.IsShortUuid)
			continue;

		if (characteristics[i].CharacteristicUuid.Value.ShortUuid ==
		    0x2A29)
			foundManufactorersNameString = true;
		if (characteristics[i].CharacteristicUuid.Value.ShortUuid ==
		    0x2A24)
			foundModelNumberString = true;
		if (characteristics[i].CharacteristicUuid.Value.ShortUuid ==
		    0x2A26)
			foundFirmwareRevisionString = true;
	}

	// clean up DIS characteristics/
	free(characteristics);

	if (!foundManufactorersNameString)
		throw STRING_RUNTIME_EXCEPTION
		    ("Can't find Manufacturer Name String Characteristic in Device Information Service.");
	if (!foundModelNumberString)
		throw STRING_RUNTIME_EXCEPTION
		    ("Can't find Model Number String Characteristic in Device Information Service.");
	if (!foundFirmwareRevisionString)
		throw STRING_RUNTIME_EXCEPTION
		    ("Can't find Firmware Revision String Characteristic in Device Information Service.");

	//
	// check the FIDO service
	//
	hResult =
	    BluetoothGATTGetCharacteristics(mServiceHandle, &mService, 0, NULL,
					    &characteristicsBufferCount,
					    BLUETOOTH_GATT_FLAG_NONE);
	if (hResult != HRESULT_FROM_WIN32(ERROR_MORE_DATA))
		throw HRESULT_RUNTIME_EXCEPTION(hResult);

	characteristics = (PBTH_LE_GATT_CHARACTERISTIC)
	    malloc(sizeof(BTH_LE_GATT_CHARACTERISTIC) *
		   characteristicsBufferCount);
	if (!characteristics)
		throw HRESULT_RUNTIME_EXCEPTION(E_OUTOFMEMORY);

	hResult =
	    BluetoothGATTGetCharacteristics(mServiceHandle, &mService,
					    characteristicsBufferCount,
					    characteristics,
					    &characteristicsCount,
					    BLUETOOTH_GATT_FLAG_NONE);
	if (FAILED(hResult)) {
		free(characteristics);
		throw HRESULT_RUNTIME_EXCEPTION(hResult);
	}

	bool foundControlPoint = false, foundControlPointLength =
	    false, foundStatus = false, foundRevision = false;
	for (i = 0; i < characteristicsCount; i++) {
		if (characteristics[i].CharacteristicUuid.Value.LongUuid ==
		    GUID_BLUETOOTHLE_FIDO_CONTROLPOINT) {
			foundControlPoint = true;
			mCharacteristicControlPoint = characteristics[i];
			continue;
		}
		if (characteristics[i].CharacteristicUuid.Value.LongUuid ==
		    GUID_BLUETOOTHLE_FIDO_CTRLPT_LEN) {
			foundControlPointLength = true;
			mCharacteristicControlPointLength = characteristics[i];
			continue;
		}
		if (characteristics[i].CharacteristicUuid.Value.LongUuid ==
		    GUID_BLUETOOTHLE_FIDO_STATUS) {
			foundStatus = true;
			mCharacteristicStatus = characteristics[i];
			continue;
		}
		if (characteristics[i].CharacteristicUuid.Value.ShortUuid ==
		    GUID_BLUETOOTHLE_FIDO_VERSION) {
			foundRevision = true;
			mCharacteristicVersion = characteristics[i];
			continue;
		}
	}
	free(characteristics);

	if (!foundControlPoint)
		STRING_RUNTIME_EXCEPTION
		    ("Could not find Control Point Characteristic in FIDO Service.");
	if (!foundControlPointLength)
		STRING_RUNTIME_EXCEPTION
		    ("Could not find Control Point Length Characteristic in FIDO Service.");
	if (!foundStatus)
		STRING_RUNTIME_EXCEPTION
		    ("Could not find Status Characteristic in FIDO Service.");
	if (!foundRevision)
		STRING_RUNTIME_EXCEPTION
		    ("Could not find U2F Version Characteristic in FIDO Service.");

	//
	// Find CCC in Status characteristic
	//
	hResult =
	    BluetoothGATTGetDescriptors(mServiceHandle, &mCharacteristicStatus,
					0, NULL, &descriptorBufferCount,
					BLUETOOTH_GATT_FLAG_NONE);
	if (hResult != HRESULT_FROM_WIN32(ERROR_MORE_DATA))
		throw HRESULT_RUNTIME_EXCEPTION(hResult);

	descriptors =
	    (PBTH_LE_GATT_DESCRIPTOR) malloc(sizeof(BTH_LE_GATT_DESCRIPTOR) *
					     descriptorBufferCount);
	if (!descriptors)
		throw HRESULT_RUNTIME_EXCEPTION(E_OUTOFMEMORY);

	hResult =
	    BluetoothGATTGetDescriptors(mServiceHandle, &mCharacteristicStatus,
					descriptorBufferCount, descriptors,
					&descriptorCount,
					BLUETOOTH_GATT_FLAG_NONE);
	if (FAILED(hResult)) {
		free(descriptors);
		throw HRESULT_RUNTIME_EXCEPTION(hResult);
	}

	bool cccFound = false;
	for (i = 0; i < descriptorCount; i++) {
		if (descriptors[i].DescriptorType !=
		    BTH_LE_GATT_DESCRIPTOR_TYPE::ClientCharacteristicConfiguration)
			continue;

		cccFound = true;
		mDescriptorCCC = descriptors[i];
	}
	free(descriptors);
	if (!cccFound)
		STRING_RUNTIME_EXCEPTION
		    ("Could not find Client Characteristic Configuration Descriptor in Status Characteristic.");

	//
	// At this point, all characteristics, services and descriptors are present and cached.
	//

	mMutex = CreateMutex(NULL, false, NULL);

	if (mMutex == NULL)
		STRING_RUNTIME_EXCEPTION("Could not create MUTEX.");
}

BleDeviceWindows::~BleDeviceWindows()
{
	CloseHandle(mDeviceHandle);
	CloseHandle(mServiceHandle);
}

void BleDeviceWindows::Lock()
{
	WaitForSingleObject(mMutex, INFINITE);
}

void BleDeviceWindows::UnLock()
{
	ReleaseMutex(mMutex);
}

bool BleDeviceWindows::hasPath(std::string path)
{
	return (path == mDeviceInstanceId);
}

ReturnValue BleDeviceWindows::RegisterNotifications(pEventHandler eventHandler)
{
	ReturnValue retval = BLEAPI_ERROR_SUCCESS;
	HRESULT hResult;
	BTH_LE_GATT_DESCRIPTOR_VALUE value;
	memset(&value, 0, sizeof(BTH_LE_GATT_DESCRIPTOR_VALUE));

	retval = BleDevice::RegisterNotifications(eventHandler);
	if (retval != BLEAPI_ERROR_SUCCESS)
		return retval;

	HANDLE regHandle;
	BLUETOOTH_GATT_VALUE_CHANGED_EVENT_REGISTRATION reg;

	reg.NumCharacteristics = 1;
	reg.Characteristics[0] = mCharacteristicStatus;

	hResult =
	    BluetoothGATTRegisterEvent(mServiceHandle,
				       BTH_LE_GATT_EVENT_TYPE::CharacteristicValueChangedEvent,
				       &reg,
				       (PFNBLUETOOTH_GATT_EVENT_CALLBACK)::OnBluetoothGattEventCallback,
				       this, &regHandle,
				       BLUETOOTH_GATT_FLAG_NONE);
	if (hResult != S_OK)
		throw HRESULT_RUNTIME_EXCEPTION(hResult);;

	value.DescriptorUuid = mDescriptorCCC.DescriptorUuid;
	value.DescriptorType = mDescriptorCCC.DescriptorType;
	value.ClientCharacteristicConfiguration.IsSubscribeToNotification =
	    TRUE;

	do {
		hResult =
		    BluetoothGATTSetDescriptorValue(mServiceHandle,
						    &mDescriptorCCC, &value,
						    (mEncryption ?
						     BLUETOOTH_GATT_FLAG_CONNECTION_ENCRYPTED
						     : 0));
	} while (hResult == HRESULT_FROM_WIN32(ERROR_DEVICE_NOT_CONNECTED));

	if (hResult != S_OK)
		throw HRESULT_RUNTIME_EXCEPTION(hResult);;

	return BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWindows::ControlPointWrite(unsigned char *buffer,
						unsigned int bufferLength)
{
	PBTH_LE_GATT_CHARACTERISTIC_VALUE valueBuffer =
	    (PBTH_LE_GATT_CHARACTERISTIC_VALUE)
	    malloc(sizeof(BTH_LE_GATT_CHARACTERISTIC_VALUE) + bufferLength);
	if (!valueBuffer)
		throw HRESULT_RUNTIME_EXCEPTION(E_OUTOFMEMORY);

	valueBuffer->DataSize = bufferLength;
	memcpy(&valueBuffer->Data, buffer, bufferLength);

	HRESULT hResult = BluetoothGATTSetCharacteristicValue(mServiceHandle,
							      &mCharacteristicControlPoint,
							      valueBuffer, NULL,
							      (mEncryption ?
							       BLUETOOTH_GATT_FLAG_CONNECTION_ENCRYPTED
							       : 0));
	if (FAILED(hResult)) {
		free(valueBuffer);
		throw HRESULT_RUNTIME_EXCEPTION(hResult);
	}

	free(valueBuffer);

	return BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWindows::ControlPointLengthRead(unsigned int *length)
{
	HRESULT hResult;
	USHORT valueBufferSize, valueSize;
	PBTH_LE_GATT_CHARACTERISTIC_VALUE value;

	if (!length)
		return BLEAPI_ERROR_INVALID_PARAMETER;

	// get the Characteristic length.
	hResult =
	    BluetoothGATTGetCharacteristicValue(mServiceHandle,
						&mCharacteristicControlPointLength,
						0, NULL, &valueBufferSize,
						BLUETOOTH_GATT_FLAG_NONE);
	if (hResult != HRESULT_FROM_WIN32(ERROR_MORE_DATA))
		throw HRESULT_RUNTIME_EXCEPTION(hResult);

	// verify this is always 2 for the ControlPointLength
	//if (valueBufferSize != 2)
	//      return BLEAPI_ERROR_REPLY_TOO_LONG;

	// get memory
	value = (PBTH_LE_GATT_CHARACTERISTIC_VALUE)
	    malloc(sizeof(BTH_LE_GATT_CHARACTERISTIC_VALUE) + valueBufferSize);
	if (!value)
		throw HRESULT_RUNTIME_EXCEPTION(E_OUTOFMEMORY);

	value->DataSize = valueBufferSize;

	// read content
	hResult =
	    BluetoothGATTGetCharacteristicValue(mServiceHandle,
						&mCharacteristicControlPointLength,
						valueBufferSize, value,
						&valueSize,
						BLUETOOTH_GATT_FLAG_FORCE_READ_FROM_DEVICE
						|
						(mEncryption ?
						 BLUETOOTH_GATT_FLAG_CONNECTION_ENCRYPTED
						 : 0));
	if (FAILED(hResult)) {
		free(value);
		throw HRESULT_RUNTIME_EXCEPTION(hResult);
	}
	// fill in data
	*length = (((USHORT) value->Data[0] << 8) | (value->Data[1]));

	return BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWindows::U2FVersionRead(unsigned char *buffer,
					     unsigned int *bufferLength)
{
	HRESULT hResult;
	USHORT valueBufferSize, valueSize;
	PBTH_LE_GATT_CHARACTERISTIC_VALUE value;

	if (!buffer || !bufferLength)
		return BLEAPI_ERROR_INVALID_PARAMETER;

	// get the Characteristic length.
	hResult =
	    BluetoothGATTGetCharacteristicValue(mServiceHandle,
						&mCharacteristicVersion, 0,
						NULL, &valueBufferSize,
						BLUETOOTH_GATT_FLAG_NONE);
	if (hResult != HRESULT_FROM_WIN32(ERROR_MORE_DATA))
		throw HRESULT_RUNTIME_EXCEPTION(hResult);

	// verify this is always 2 for the ControlPointLength
	if (valueBufferSize > *bufferLength)
		return BLEAPI_ERROR_REPLY_TOO_LONG;

	// get memory
	value = (PBTH_LE_GATT_CHARACTERISTIC_VALUE)
	    malloc(sizeof(BTH_LE_GATT_CHARACTERISTIC_VALUE) + valueBufferSize);
	if (!value)
		throw HRESULT_RUNTIME_EXCEPTION(E_OUTOFMEMORY);

	value->DataSize = valueBufferSize;

	// read content
	hResult =
	    BluetoothGATTGetCharacteristicValue(mServiceHandle,
						&mCharacteristicVersion,
						valueBufferSize, value,
						&valueSize,
						BLUETOOTH_GATT_FLAG_FORCE_READ_FROM_DEVICE
						|
						(mEncryption ?
						 BLUETOOTH_GATT_FLAG_CONNECTION_ENCRYPTED
						 : 0));
	if (FAILED(hResult)) {
		free(value);
		throw HRESULT_RUNTIME_EXCEPTION(hResult);
	}
	// return data
	memcpy(buffer, value->Data, valueBufferSize);
	*bufferLength = valueBufferSize;

	return BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWindows::Sleep(unsigned int miliseconds)
{
	::Sleep(miliseconds);

	return BLEAPI_ERROR_SUCCESS;
}

uint64_t BleDeviceWindows::TimeMs()
{
	return (uint64_t) GetTickCount64();
}

// device Identification
std::string BleDeviceWindows::Identifier()
{
	return mDeviceInstanceId;
}
