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

#include "BleApiWinRT.h"
#include "BleDeviceWinRT.h"
#include <ppltasks.h>
#include <locale>
#include <codecvt>

using namespace Platform;
using namespace Concurrency;
using namespace Windows::Devices::Enumeration;
using namespace Windows::Devices::Bluetooth;
using namespace Windows::Devices::Bluetooth::GenericAttributeProfile;

static const Guid FIDO_SERVICE_GUID(0x0000FFFD, 0x0000, 0x1000, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB);

BleApiWinRT::BleApiWinRT(bool encryption, bool logging)
  : BleApi(encryption, logging)
{
  RoInitialize(RO_INIT_TYPE::RO_INIT_MULTITHREADED);
}

BleApiWinRT::~BleApiWinRT(void)
{
  RoUninitialize();
}

std::vector<BleDevice*> BleApiWinRT::findDevices()
{
  std::vector < BleDevice * >list;
  using convert_type = std::codecvt_utf8<wchar_t>;
  std::wstring_convert<convert_type, wchar_t> converter;

  try {
    String ^deviceSelector = GattDeviceService::GetDeviceSelectorFromUuid(FIDO_SERVICE_GUID);
    //String ^deviceSelector = BluetoothLEDevice::GetDeviceSelector();
    DeviceInformationCollection ^devices = create_task(DeviceInformation::FindAllAsync(deviceSelector)).get();

    for (unsigned int i = 0; i < devices->Size; i++) {
      DeviceInformation ^devInfo = devices->GetAt(i);
      BluetoothLEDevice ^dev = create_task(BluetoothLEDevice::FromIdAsync(devInfo->Id)).get();
      std::string id = converter.to_bytes(devInfo->Id->Data());

      // find the path in the known devices.
      unsigned int j;
      for (j = 0; j < mDeviceList.size(); j++) {
        if (!((BleDeviceWinRT *)mDeviceList[j])->hasPath(id))
          continue;

        // found
        list.push_back(mDeviceList[j]);
        break;
      }

      if (i != mDeviceList.size())
        continue;

      BleDevice *ourdev = static_cast<BleDevice *>(new BleDeviceWinRT(this, id, dev, mEncryption, mLogging));
      if (!ourdev)
        continue;

      list.push_back(ourdev);
      mDeviceList.push_back(ourdev);
    };

    delete devices;
  }
  catch (std::exception e)
  {
      
  };

  return list;
}
