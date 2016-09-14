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

#include <BleDeviceWinRT.h>
#include <ppltasks.h>

using namespace Platform;
using namespace Concurrency;
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::Devices::Enumeration;
using namespace Windows::Devices::Bluetooth;
using namespace Windows::Devices::Bluetooth::GenericAttributeProfile;
using namespace Windows::Storage::Streams;

#define STRING_RUNTIME_EXCEPTION(x)		std::runtime_error( __FILE__ + std::to_string(__LINE__) + x)

#define CHECK_SERVICE(maDevice, maService)  try { if (maDevice->GetGattService(GattServiceUuids::maService) == nullptr) throw; } catch(...) { STRING_RUNTIME_EXCEPTION("Device does not support " #maService); }

#define CHECK_CHARACTERISTIC_PROPERTY_SET(c, p)  if ((c->CharacteristicProperties & GattCharacteristicProperties::p) != GattCharacteristicProperties::p) throw STRING_RUNTIME_EXCEPTION(#c " does not support " #p);

static const Guid FIDO_SERVICE_GUID(0x0000FFFD, 0x0000, 0x1000, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB);
static const Guid FIDO_CHARACTERISTIC_CONTROLPOINTLENGTH_GUID(0xF1D0FFF3, 0xDEAA, 0xECEE, 0xB4, 0x2F, 0xC9, 0xBA, 0x7E, 0xD6, 0x23, 0xBB);
static const Guid FIDO_CHARACTERISTIC_CONTROLPOINT_GUID(0xF1D0FFF1, 0xDEAA, 0xECEE, 0xB4, 0x2F, 0xC9, 0xBA, 0x7E, 0xD6, 0x23, 0xBB);
static const Guid FIDO_CHARACTERISTIC_STATUS_GUID(0xF1D0FFF2, 0xDEAA, 0xECEE, 0xB4, 0x2F, 0xC9, 0xBA, 0x7E, 0xD6, 0x23, 0xBB);
static const Guid FIDO_CHARACTERISTIC_VERSION_GUID(0x00002A28, 0x0000, 0x1000, 0x80, 0x00, 0x00,0x80,0x5F, 0x9B, 0x34, 0xFB);
static const Guid FIDO_CHARACTERISTIC_VERSIONBITFIELD_GUID(0xF1D0FFF4, 0xDEAA, 0xECEE, 0xB4, 0x2F, 0xC9, 0xBA, 0x7E, 0xD6, 0x23, 0xB);

//
//   Private utility functions to convert data between C++ and CX
//

IBuffer ^ConvertToIBuffer(unsigned char * buffer, unsigned int bufferLength)
{
  auto dataWriter = ref new DataWriter();
  auto a = ref new Array<unsigned char>(buffer, bufferLength);
  dataWriter->WriteBytes(a);
  auto b = dataWriter->DetachBuffer();
  return b;
}

ReturnValue ConvertFromIBuffer(IBuffer ^incoming, unsigned char *buffer, unsigned int &bufferLength)
{
  if (bufferLength < incoming->Length)
    return ReturnValue::BLEAPI_ERROR_BUFFER_TOO_SMALL;

  auto dataReader = DataReader::FromBuffer(incoming);
  auto a = ref new Array<unsigned char>(bufferLength);
  dataReader->ReadBytes(a);

  memcpy(buffer, a->Data, a->Length);
  bufferLength = a->Length;

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

//
//  A small class to wrap our C++ notification handler in a CX notification handler.
//
ref class BleDeviceEventhandlerWrapper sealed
{
internal:
  BleDeviceEventhandlerWrapper(BleDeviceWinRT *dev) : mDevice(dev) {};

public:
  void OnNotification(GattCharacteristic^ sender, GattValueChangedEventArgs^ args)
  {
    mDevice->OnNotification(sender, args);
  }

private:
  BleDeviceWinRT *mDevice;
};

//
//  methods
//

BleDeviceWinRT::BleDeviceWinRT(pBleApi pBleApi, std::string deviceInstanceId, Windows::Devices::Bluetooth::BluetoothLEDevice ^ device, bool encrypt, bool logging)
  : BleDevice(encrypt, logging)
  , mDevice(device)
  , mDeviceInstanceId(deviceInstanceId)
{
  CHECK_SERVICE(mDevice, DeviceInformation);


  mService = mDevice->GetGattService(FIDO_SERVICE_GUID);
  if (!mService)
    STRING_RUNTIME_EXCEPTION("Could not get Service.");

  // control point length
  auto 
  characteristics =  mService->GetCharacteristics(FIDO_CHARACTERISTIC_CONTROLPOINTLENGTH_GUID);
  if (characteristics->Size == 0)
    throw STRING_RUNTIME_EXCEPTION("Could not get ControlPoint Length Characteristic.");

  mCharacteristicControlPointLength = characteristics->GetAt(0);

  CHECK_CHARACTERISTIC_PROPERTY_SET(mCharacteristicControlPointLength, Read);

  // control point
  characteristics = mService->GetCharacteristics(FIDO_CHARACTERISTIC_CONTROLPOINT_GUID);
  if (characteristics->Size == 0)
    throw STRING_RUNTIME_EXCEPTION("Could not get ControlPoint Characteristic.");

  mCharacteristicControlPoint = characteristics->GetAt(0);

  CHECK_CHARACTERISTIC_PROPERTY_SET(mCharacteristicControlPoint, WriteWithoutResponse);

  // status
  characteristics = mService->GetCharacteristics(FIDO_CHARACTERISTIC_STATUS_GUID);
  if (characteristics->Size == 0)
    throw STRING_RUNTIME_EXCEPTION("Could not get Status Characteristic.");

  mCharacteristicStatus = characteristics->GetAt(0);
  CHECK_CHARACTERISTIC_PROPERTY_SET(mCharacteristicStatus, Notify);

  // version
  bool v10version = false, v11version = false;
  characteristics = mService->GetCharacteristics(FIDO_CHARACTERISTIC_VERSION_GUID);
  if (characteristics->Size > 0) {
    v10version = true;
    mCharacteristicVersion = characteristics->GetAt(0);

    CHECK_CHARACTERISTIC_PROPERTY_SET(mCharacteristicVersion, Read);
  }
  characteristics = mService->GetCharacteristics(FIDO_CHARACTERISTIC_VERSIONBITFIELD_GUID);
  if (characteristics->Size > 0) {
    v11version = true;
    mCharacteristicVersionBitfield = characteristics->GetAt(0);

    CHECK_CHARACTERISTIC_PROPERTY_SET(mCharacteristicVersionBitfield, Read);
  }

  if (!v10version && !v11version) 
    throw STRING_RUNTIME_EXCEPTION("Could not get Version or VersionBitfield Characteristic.");
  
  // mutex init
  mMutex = CreateMutex(NULL, false, NULL);
  if (mMutex == NULL)
    STRING_RUNTIME_EXCEPTION("Could not create MUTEX.");
}

BleDeviceWinRT::~BleDeviceWinRT()
{
  if (mNotificationsRegistered)
    mCharacteristicStatus->ValueChanged -= mRegistrationToken;

  CloseHandle(mMutex);
}

bool BleDeviceWinRT::hasPath(std::string path)
{
  return (mDeviceInstanceId == path);
}

ReturnValue BleDeviceWinRT::ControlPointWrite(unsigned char * buffer, unsigned int bufferLength)
{
  IBuffer ^b = ConvertToIBuffer(buffer, bufferLength);

  // write characteristic
  GattCommunicationStatus status = create_task(mCharacteristicControlPoint->WriteValueAsync(b, GattWriteOption::WriteWithoutResponse)).get();
  if (status != GattCommunicationStatus::Success)
    return ReturnValue::BLEAPI_ERROR_UNKNOWN_ERROR;

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWinRT::ControlPointLengthRead(unsigned int * length)
{
  ReturnValue retval;
  unsigned char buffer[512];
  unsigned int bufferLength = sizeof (buffer);

  // read characteristic
  GattReadResult ^result = create_task(mCharacteristicControlPoint->ReadValueAsync()).get();
  if (result->Status != GattCommunicationStatus::Success)
    return ReturnValue::BLEAPI_ERROR_UNKNOWN_ERROR;

  // convert to C++ data.
  retval = ConvertFromIBuffer(result->Value, buffer, bufferLength);
  if (!retval)
    return retval;

  // calculate length
  *length = 0;
  for (unsigned int i = 0; i < bufferLength; i++)
  {
    *length <<= 8;
    *length += buffer[i];
  }

  // validate length
  if ((*length < 20)||(*length > 512))
    throw STRING_RUNTIME_EXCEPTION("ControlPointLength has illegal value.");

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWinRT::U2FVersionRead(unsigned char * buffer, unsigned int * bufferLength)
{
  ReturnValue retval;

  // read characteristic
  GattReadResult ^result = create_task(mCharacteristicVersion->ReadValueAsync()).get();
  if (result->Status != GattCommunicationStatus::Success)
    return ReturnValue::BLEAPI_ERROR_UNKNOWN_ERROR;

  // convert to C++ data.
  retval = ConvertFromIBuffer(result->Value, buffer, *bufferLength);
  if (!retval)
    return retval;

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWinRT::RegisterNotifications(pEventHandler eventHandler)
{
  if (!mNotificationsRegistered) {
    auto wrapper = ref new BleDeviceEventhandlerWrapper(this);
    auto eh = ref new TypedEventHandler<GattCharacteristic^, GattValueChangedEventArgs^>(
      wrapper, &BleDeviceEventhandlerWrapper::OnNotification
      );

    mRegistrationToken = mCharacteristicStatus->ValueChanged += eh;
    mNotificationsRegistered = true;
  }

  mNotificationHandlers.push_back(eventHandler);

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWinRT::Sleep(unsigned int miliseconds)
{
  ::Sleep(miliseconds);

  return BLEAPI_ERROR_SUCCESS;
}

uint64_t BleDeviceWinRT::TimeMs()
{
  return (uint64_t)GetTickCount64();
}

std::string BleDeviceWinRT::Identifier()
{
  return mDeviceInstanceId;
}

void BleDeviceWinRT::Lock()
{
  WaitForSingleObject(mMutex, INFINITE);
}

void BleDeviceWinRT::UnLock()
{
  ReleaseMutex(mMutex);
}

void BleDeviceWinRT::OnNotification(GattCharacteristic^ sender, GattValueChangedEventArgs^ args)
{

}