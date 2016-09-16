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

#ifndef _BLEAPI_BLEDEVICEWINRT_H_
#define _BLEAPI_BLEDEVICEWINRT_H_

#include "BleApi.h"
#include "BleDevice.h"

#include <windows.devices.bluetooth.h>
#include <vector>

class BleDeviceWinRT : public BleDevice {
public:
  BleDeviceWinRT(pBleApi pBleApi, std::string deviceInstanceId, Windows::Devices::Bluetooth::BluetoothLEDevice ^device,
    BleApiConfiguration &configuration);
  ~BleDeviceWinRT();

  bool hasPath(std::string path);

public:
  virtual ReturnValue Verify();

  virtual ReturnValue ControlPointWrite(unsigned char *buffer,
    unsigned int bufferLength);
  virtual ReturnValue ControlPointLengthRead(unsigned int *length);
  virtual ReturnValue U2FVersionRead(unsigned char *buffer,
    unsigned int *bufferLength);
  virtual ReturnValue U2FVersionBitfieldRead(unsigned char *buffer,
    unsigned int *bufferLength);
  virtual ReturnValue RegisterNotifications(pEventHandler eventHandler);

  virtual ReturnValue Sleep(unsigned int miliseconds);
  virtual uint64_t TimeMs();

  // device Identification
  virtual std::string Identifier();

  // version management
  virtual bool SupportsVersion(U2FVersion version);
  virtual bool SelectVersion(U2FVersion version, bool force = false);

  // bluetooth layer interface
  virtual bool IsConnected();
  virtual bool IsPaired();
  virtual bool IsAdvertising();
  virtual void Report();

protected:
  virtual void Lock();
  virtual void UnLock();

  virtual void OnNotification(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic^ sender, Windows::Devices::Bluetooth::GenericAttributeProfile::GattValueChangedEventArgs^ args);
  friend ref class BleDeviceEventhandlerWrapper;

protected:
  std::string mDeviceInstanceId;
  HANDLE mMutex;
  bool mNotificationsRegistered;
  Windows::Foundation::EventRegistrationToken mRegistrationToken;
  ref class BleDeviceEventhandlerWrapper  ^mEHWrapper;

  std::vector<pEventHandler>  mNotificationHandlers;
  Windows::Devices::Bluetooth::BluetoothLEDevice ^mDevice;
  Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService ^mService;
  Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic
    ^mCharacteristicControlPointLength, ^mCharacteristicControlPoint,
    ^mCharacteristicStatus,
    ^mCharacteristicVersion, ^mCharacteristicVersionBitfield;
};

#endif				/* _BLEAPI_BLEDEVICEWINRT_H_ */
