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
#include <iostream>
#include <ppltasks.h>
#include <locale>
#include <codecvt>
#include <collection.h>
#include <comdef.h>

#include <sddl.h>

using namespace Platform;
using namespace Platform::Collections;
using namespace Concurrency;
using namespace Windows::Foundation::Collections;
using namespace Windows::Devices::Enumeration;
using namespace Windows::Devices::Bluetooth;
using namespace Windows::Devices::Bluetooth::GenericAttributeProfile;
using namespace Windows::Devices::Radios;

static const Guid FIDO_SERVICE_GUID(0x0000FFFD, 0x0000, 0x1000, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB);

inline std::runtime_error hresult_exception(std::string file, int line, HRESULT result)
{
  _com_error err(result, NULL, false);

  std::string m;
  m.append(file);
  m.append(":");
#if defined(_MSC_VER) && (_MSC_VER <= 1600 )
  m.append(std::to_string(static_cast < long long >(line)));
#else
  m.append(std::to_string(line));
#endif
  m.append(" ");
  m.append((const char *)err.ErrorMessage());
  return std::runtime_error(m);
}
#define HRESULT_RUNTIME_EXCEPTION(x)		hresult_exception(__FILE__, __LINE__, x);
#define STRING_RUNTIME_EXCEPTION(x)		std::runtime_error( __FILE__ ":" + std::to_string(__LINE__) + ": " + x)
#define CX_EXCEPTION(x)               HRESULT_RUNTIME_EXCEPTION(x->HResult)

// From: https://github.com/pauldotknopf/WindowsSDK7-Samples/blob/master/com/fundamentals/dcom/dcomperm/SDMgmt.Cpp
DWORD MakeSDAbsolute(
  PSECURITY_DESCRIPTOR psidOld,
  PSECURITY_DESCRIPTOR *psidNew
)
{
  PSECURITY_DESCRIPTOR  pSid = NULL;
  DWORD                 cbDescriptor = 0;
  DWORD                 cbDacl = 0;
  DWORD                 cbSacl = 0;
  DWORD                 cbOwnerSID = 0;
  DWORD                 cbGroupSID = 0;
  PACL                  pDacl = NULL;
  PACL                  pSacl = NULL;
  PSID                  psidOwner = NULL;
  PSID                  psidGroup = NULL;
  BOOL                  fPresent = FALSE;
  BOOL                  fSystemDefault = FALSE;
  DWORD                 dwReturnValue = ERROR_SUCCESS;

  // Get SACL
  if (!GetSecurityDescriptorSacl(psidOld, &fPresent, &pSacl, &fSystemDefault))
  {
    dwReturnValue = GetLastError();
    goto CLEANUP;
  }

  if (pSacl && fPresent)
  {
    cbSacl = pSacl->AclSize;
  }

  // Get DACL
  if (!GetSecurityDescriptorDacl(psidOld, &fPresent, &pDacl, &fSystemDefault))
  {
    dwReturnValue = GetLastError();
    goto CLEANUP;
  }

  if (pDacl && fPresent)
  {
    cbDacl = pDacl->AclSize;
  }

  // Get Owner
  if (!GetSecurityDescriptorOwner(psidOld, &psidOwner, &fSystemDefault))
  {
    dwReturnValue = GetLastError();
    goto CLEANUP;
  }

  cbOwnerSID = GetLengthSid(psidOwner);

  // Get Group
  if (!GetSecurityDescriptorGroup(psidOld, &psidGroup, &fSystemDefault))
  {
    dwReturnValue = GetLastError();
    goto CLEANUP;
  }

  cbGroupSID = GetLengthSid(psidGroup);

  // Do the conversion
  cbDescriptor = 0;

  MakeAbsoluteSD(psidOld, pSid, &cbDescriptor, pDacl, &cbDacl, pSacl,
    &cbSacl, psidOwner, &cbOwnerSID, psidGroup,
    &cbGroupSID);

  pSid = (PSECURITY_DESCRIPTOR)malloc(cbDescriptor);
  if (!pSid)
  {
    dwReturnValue = ERROR_OUTOFMEMORY;
    goto CLEANUP;
  }

  ZeroMemory(pSid, cbDescriptor);

  if (!InitializeSecurityDescriptor(pSid, SECURITY_DESCRIPTOR_REVISION))
  {
    dwReturnValue = GetLastError();
    goto CLEANUP;
  }

  if (!MakeAbsoluteSD(psidOld, pSid, &cbDescriptor, pDacl, &cbDacl, pSacl,
    &cbSacl, psidOwner, &cbOwnerSID, psidGroup,
    &cbGroupSID))
  {
    dwReturnValue = GetLastError();
    goto CLEANUP;
  }

CLEANUP:

  if (dwReturnValue != ERROR_SUCCESS && pSid)
  {
    free(pSid);
    pSid = NULL;
  }

  *psidNew = pSid;

  return dwReturnValue;
}


BleApiWinRT::BleApiWinRT(BleApiConfiguration &configuration)
  : BleApi(configuration)
{
  RoInitialize(RO_INIT_TYPE::RO_INIT_MULTITHREADED);

  const char* security = "O:BAG:BAD:(A;;0x7;;;PS)(A;;0x3;;;SY)(A;;0x7;;;BA)(A;;0x3;;;AC)(A;;0x3;;;LS)(A;;0x3;;;NS)";

  PSECURITY_DESCRIPTOR pSecurityDescriptor;
  ULONG securityDescriptorSize;

  if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
    security,
    SDDL_REVISION_1,
    &pSecurityDescriptor,
    &securityDescriptorSize))
  {
    throw STRING_RUNTIME_EXCEPTION("ConvertStringSecurityDescriptorToSecurityDescriptor failed.");
  }

  // MakeSDAbsolute as defined in
  // https://github.com/pauldotknopf/WindowsSDK7-Samples/blob/master/com/fundamentals/dcom/dcomperm/SDMgmt.Cpp
  PSECURITY_DESCRIPTOR pAbsoluteSecurityDescriptor = NULL;
  MakeSDAbsolute(pSecurityDescriptor, &pAbsoluteSecurityDescriptor);

  HRESULT hResult = CoInitializeSecurity(
    pAbsoluteSecurityDescriptor, // Converted from the above string.
    -1,
    nullptr,
    nullptr,
    RPC_C_AUTHN_LEVEL_DEFAULT,
    RPC_C_IMP_LEVEL_IDENTIFY,
    NULL,
    EOAC_NONE,
    nullptr);
  if (FAILED(hResult))
  {
    throw HRESULT_RUNTIME_EXCEPTION(hResult);
  }
}

BleApiWinRT::~BleApiWinRT(void)
{
  RoUninitialize();
}

std::vector<BleDevice*> BleApiWinRT::findDevices()
{
  try {
    std::vector < BleDevice * >list;
    using convert_type = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_type, wchar_t> converter;

    Vector<String ^> properties(1);
    properties.SetAt(0, ref new String(L"System.Devices.ContainerId"));

    // get a list of all paired Bluetooth LE devices.
    //   It is possible to select the device with the FIDO service but then we don't have access to the main device
    //   and we''ll have to convert to a normal device later through the bluetooth address.
    String ^deviceSelector = BluetoothLEDevice::GetDeviceSelector();
    DeviceInformationCollection ^devices = create_task(DeviceInformation::FindAllAsync(deviceSelector, %properties)).get();

    // run over the list, filter for devices with a FIDO service and add them to the mDeviceList if unknown.
    for (unsigned int i = 0; i < devices->Size; i++) {
      DeviceInformation ^devInfo = devices->GetAt(i);
      BluetoothLEDevice ^dev = create_task(BluetoothLEDevice::FromIdAsync(devInfo->Id)).get();
      std::string id = converter.to_bytes(dev->DeviceId->Data());

      // check all services for FIDO service.
      unsigned int j, n;
      auto services = dev->GattServices;
      for (j = 0, n = services->Size; j < n; j++)
      {
        if (services->GetAt(j)->Uuid == FIDO_SERVICE_GUID)
          break;
      }
      if (j == n)
        continue;

      // find the path in the known devices.
      for (j = 0, n = (unsigned int)mDeviceList.size(); j < n; j++) {
        if (!((BleDeviceWinRT *)mDeviceList[j])->hasPath(id))
          continue;

        // found
        list.push_back(mDeviceList[j]);
        break;
      }

      if (j != n)
        continue;

      // create a new device.
      BleDevice *ourdev = static_cast<BleDevice *>(new BleDeviceWinRT(this, id, dev, mConfiguration));
      if (!ourdev)
        continue;

      list.push_back(ourdev);
      mDeviceList.push_back(ourdev);
    };

    delete devices;

    // build a list of old devices.
    unsigned int i, n;
    std::vector < BleDevice * > oldDevices;
    // run over the device list
    for (i = 0, n = (unsigned int)mDeviceList.size(); i < n; i++)
    {
      unsigned int j, m;
      std::string id = mDeviceList[i]->Identifier();

      // if they aren't in the new list, they have disappeared.
      for (j = 0, m = (unsigned int)list.size(); j < m; j++) {
        if (!((BleDeviceWinRT *)list[j])->hasPath(id))
          continue;

        break;
      }
      if (j < m)
        continue;

      oldDevices.push_back(mDeviceList[i]);
    }

    // remove old devices from device list.
    mDeviceList = list;

    // clean up old devices
    for (i = 0, n = (unsigned int)oldDevices.size(); i < n; i++) {
      auto d = oldDevices.back();
      oldDevices.pop_back();
      delete d;
    }

    return list;
  }
  catch (std::exception &e)
  {
    throw STRING_RUNTIME_EXCEPTION(e.what());
  }
  catch (Exception ^e)
  {
    throw CX_EXCEPTION(e);
  }
  catch (...)
  {
    throw STRING_RUNTIME_EXCEPTION("Unknown error pairing.");
  }

}

bool BleApiWinRT::IsEnabled()
{
  try {
    // check if there is a bluetooth radio.
    auto radios = create_task(Radio::GetRadiosAsync()).get();
    bool found = false, on = false;
    for (auto i = radios->First(); (!found || (!on)) && i->HasCurrent; i->MoveNext())
    {
      if (i->Current->Kind == RadioKind::Bluetooth)
      {
        found = true;
        if (i->Current->State == RadioState::On)
          on = true;
      }
    }
    if (!found) {
      std::cout << "Bluetooth radio not found." << std::endl;
      return false;
    }
    if (!on) {
      std::cout << "Bluetooth radio found but disabled." << std::endl;
      return false;
    }

    return true;
  }
  catch (...) {
    return false;
  }
}
