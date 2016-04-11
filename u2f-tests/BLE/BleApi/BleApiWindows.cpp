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

#include <iostream>

using namespace std;

#include "BleApiWindows.h"
#include "BleDeviceWindows.h"

#include <windows.h>
#include <initguid.h>
#include <guiddef.h>
#include <setupapi.h>
#include <string>
#include <vector>
#include <cfgmgr32.h>

#include <BluetoothLEApis.h>
#include <BluetoothAPIs.h>

#include <comdef.h>

#include <stdint.h>

#pragma comment(lib, "Setupapi.lib")
#pragma comment(lib, "BluetoothApis.lib")
#pragma comment(lib, "Bthprops.lib")

DEFINE_GUID(GUID_BLUETOOTHLE_FIDO_SERVICE, 0x0000FFFD, 0x0000, 0x1000, 0x80,
	    0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB);

#define HRESULT_RUNTIME_EXCEPTION(x)		hresult_exception(__FILE__, __LINE__, x);

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

static int GetDevicePath(IN HDEVINFO p_hDevInfo,
			 IN SP_DEVINFO_DATA * p_pDeviceInfoData,
			 IN GUID p_InterfaceServiceGuid, OUT string & p_Path)
{
	// Get device interface
	SP_DEVICE_INTERFACE_DATA DeviceInterfaceData;
	DeviceInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
	BOOL isSuccess = SetupDiEnumDeviceInterfaces(p_hDevInfo, p_pDeviceInfoData, &p_InterfaceServiceGuid, 0, &DeviceInterfaceData);	// TODO Why is MemberIndex == 0
	if (!isSuccess)
		throw HRESULT_RUNTIME_EXCEPTION(GetLastError());

	// Get length of interface detail data
	DWORD interfaceDetailLen = 0;
	isSuccess =
	    SetupDiGetDeviceInterfaceDetail(p_hDevInfo, &DeviceInterfaceData,
					    NULL, 0, &interfaceDetailLen, NULL);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		isSuccess = TRUE;
	if (!isSuccess)
		throw HRESULT_RUNTIME_EXCEPTION(GetLastError());

	// Allocate
	SP_DEVICE_INTERFACE_DETAIL_DATA *pInterfaceDetail =
	    (SP_DEVICE_INTERFACE_DETAIL_DATA *) malloc(interfaceDetailLen);
	if (!pInterfaceDetail)
		throw HRESULT_RUNTIME_EXCEPTION(E_OUTOFMEMORY);

	// Get interface detail data 
	pInterfaceDetail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
	isSuccess =
	    SetupDiGetDeviceInterfaceDetail(p_hDevInfo, &DeviceInterfaceData,
					    pInterfaceDetail,
					    interfaceDetailLen, NULL, NULL);

	if (!isSuccess) {
		HRESULT hResult = GetLastError();

		free(pInterfaceDetail);

		throw HRESULT_RUNTIME_EXCEPTION(hResult);
	}

	p_Path = ((char *)pInterfaceDetail->DevicePath);
	free(pInterfaceDetail);

	return BLEAPI_ERROR_SUCCESS;
}

int GetDeviceInstanceId(IN DWORD devInst, OUT string & p_DeviceInstanceId)
{
	ULONG idSize;
	int ret = CM_Get_Device_ID_Size(&idSize, devInst, 0);
	if (ret != CR_SUCCESS)
		return BLEAPI_ERROR_UNKNOWN_ERROR;

	std::vector < TCHAR > idBuf(idSize + 1);
	ret = CM_Get_Device_ID(devInst, idBuf.data(), (ULONG) idBuf.size(), 0);
	if (ret != CR_SUCCESS)
		return BLEAPI_ERROR_UNKNOWN_ERROR;

	p_DeviceInstanceId = (char *)idBuf.data();
	return BLEAPI_ERROR_SUCCESS;
}

int GetServiceHandle(IN string p_DevInstanceId, OUT HANDLE & p_hService)
{
	HDEVINFO hDevInfo =
	    SetupDiGetClassDevs(&GUID_BLUETOOTHLE_FIDO_SERVICE, 0, 0,
				DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
	size_t devCnt = 0;

	for (;; ++devCnt) {
		SP_DEVINFO_DATA deviceInfoData = { 0 };
		deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
		SetupDiEnumDeviceInfo(hDevInfo, (DWORD) devCnt,
				      &deviceInfoData);

		DWORD lastError = GetLastError();
		if (lastError == ERROR_NO_MORE_ITEMS)
			break;
		else if (lastError != ERROR_SUCCESS)
			throw HRESULT_RUNTIME_EXCEPTION(lastError);

		// Compare if the parent of the service is the same as the BLE device

		DWORD devInstParent = 0;
		CONFIGRET ret =
		    CM_Get_Parent(&devInstParent, deviceInfoData.DevInst, 0);
		if (ret != CR_SUCCESS)
			return BLEAPI_ERROR_UNKNOWN_ERROR;

		string deviceInstanceId;
		int result =
		    GetDeviceInstanceId(devInstParent, deviceInstanceId);
		if (result != BLEAPI_ERROR_SUCCESS)
			return result;

		if (deviceInstanceId.compare(p_DevInstanceId) == 0) {
			string path;
			result =
			    GetDevicePath(hDevInfo, &deviceInfoData,
					  GUID_BLUETOOTHLE_FIDO_SERVICE, path);
			if (result != BLEAPI_ERROR_SUCCESS)
				return result;

			p_hService =
			    CreateFile(path.c_str(),
				       GENERIC_WRITE | GENERIC_READ,
				       FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
				       OPEN_EXISTING, 0, NULL);
			if (!p_hService)
				throw HRESULT_RUNTIME_EXCEPTION(GetLastError());

			return BLEAPI_ERROR_SUCCESS;
		}
	}
	return BLEAPI_ERROR_NOT_FOUND;
}

 BleApiWindows::BleApiWindows(bool encryption):
BleApi(encryption)
{
};

BleApiWindows::~BleApiWindows(void)
{
}

std::vector < BleDevice * >BleApiWindows::findDevices()
{
	std::vector < BleDevice * >list;

	int result;
	GUID btInterfaceDeviceGuid = GUID_BLUETOOTHLE_DEVICE_INTERFACE;
	// Create device info list
	HDEVINFO hDevInfo = SetupDiGetClassDevs(&btInterfaceDeviceGuid, 0, 0,
						DIGCF_DEVICEINTERFACE |
						DIGCF_PRESENT);

	size_t devCnt = 0;
	for (size_t infoCnt = 0;; ++infoCnt) {
		// get device information
		SP_DEVINFO_DATA deviceInfoData = { 0 };
		deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
		SetupDiEnumDeviceInfo(hDevInfo, (DWORD) infoCnt,
				      &deviceInfoData);
		DWORD lastError = GetLastError();
		if (lastError == ERROR_NO_MORE_ITEMS)
			break;
		else if (lastError != ERROR_SUCCESS)
			throw HRESULT_RUNTIME_EXCEPTION(lastError);

		// retrieve device path.
		string path;
		result =
		    GetDevicePath(hDevInfo, &deviceInfoData,
				  btInterfaceDeviceGuid, path);
		if (result != BLEAPI_ERROR_SUCCESS)
			continue;

		// find the path in the known devices.
		unsigned int i;
		for (i = 0; i < mDeviceList.size(); i++) {
			if (!((BleDeviceWindows *) mDeviceList[i])->hasPath
			    (path))
				continue;

			// found
			list.push_back(mDeviceList[i]);
			break;
		}
		if (i != mDeviceList.size())
			continue;

		// Try to find and open the service
		string deviceInstanceId;
		result =
		    GetDeviceInstanceId(deviceInfoData.DevInst,
					deviceInstanceId);
		if (result != BLEAPI_ERROR_SUCCESS)
			break;

		// create service handle
		HANDLE serviceHandle;
		result = GetServiceHandle(deviceInstanceId, serviceHandle);
		if (result == BLEAPI_ERROR_NOT_FOUND)
			continue;
		if (result != BLEAPI_ERROR_SUCCESS)
			break;

		// create device handle
		HANDLE devHandle =
		    CreateFile(path.c_str(), GENERIC_WRITE | GENERIC_READ,
			       FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			       OPEN_EXISTING, 0, NULL);
		if (devHandle == NULL) {
			CloseHandle(serviceHandle);
			throw HRESULT_RUNTIME_EXCEPTION(GetLastError());
		}
		// create BleDevice and store it.
		// ownership of the handles moves to BleDeviceWindows
		BleDevice *dev =
		    (BleDevice *) new BleDeviceWindows(this, deviceInstanceId,
						       devHandle,
						       serviceHandle,
						       mEncryption);
		list.push_back(dev);
		mDeviceList.push_back(dev);
	}

	return list;
}
