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
#include <ppltasks.h>
#include <comdef.h>
#include <iostream>
#include <stdexcept>

#include <BleDeviceWinRT.h>

using namespace Platform;
using namespace Concurrency;
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::Devices::Enumeration;
using namespace Windows::Devices::Bluetooth;
using namespace Windows::Devices::Bluetooth::GenericAttributeProfile;
using namespace Windows::Storage::Streams;
using namespace Windows::Security::Cryptography;

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
#define STRING_RUNTIME_EXCEPTION(x)		std::runtime_error( __FILE__ + std::to_string(__LINE__) + x)

#define CHECK_SERVICE(maDevice, maService)  try { if (maDevice->GetGattService(GattServiceUuids::maService) == nullptr) throw; } \
      catch (Platform::Exception^ comException) \
            { HRESULT_RUNTIME_EXCEPTION( comException->HResult ); } \
      catch (const std::exception& e) \
            { STRING_RUNTIME_EXCEPTION( e.what() ); } \
      catch (...) \
            { STRING_RUNTIME_EXCEPTION( "Device does not support " #maService ); } 

#define CHECK_CHARACTERISTIC_PROPERTY_SET(c, p)  if ((c->CharacteristicProperties & GattCharacteristicProperties::p) != GattCharacteristicProperties::p) throw STRING_RUNTIME_EXCEPTION(#c " does not support " #p);

static const Guid FIDO_SERVICE_GUID(0x0000FFFD, 0x0000, 0x1000, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB);
static const Guid FIDO_CHARACTERISTIC_CONTROLPOINTLENGTH_GUID(0xF1D0FFF3, 0xDEAA, 0xECEE, 0xB4, 0x2F, 0xC9, 0xBA, 0x7E, 0xD6, 0x23, 0xBB);
static const Guid FIDO_CHARACTERISTIC_CONTROLPOINT_GUID(0xF1D0FFF1, 0xDEAA, 0xECEE, 0xB4, 0x2F, 0xC9, 0xBA, 0x7E, 0xD6, 0x23, 0xBB);
static const Guid FIDO_CHARACTERISTIC_STATUS_GUID(0xF1D0FFF2, 0xDEAA, 0xECEE, 0xB4, 0x2F, 0xC9, 0xBA, 0x7E, 0xD6, 0x23, 0xBB);
static const Guid FIDO_CHARACTERISTIC_VERSION_GUID(0x00002A28, 0x0000, 0x1000, 0x80, 0x00, 0x00,0x80,0x5F, 0x9B, 0x34, 0xFB);
static const Guid FIDO_CHARACTERISTIC_VERSIONBITFIELD_GUID(0xF1D0FFF4, 0xDEAA, 0xECEE, 0xB4, 0x2F, 0xC9, 0xBA, 0x7E, 0xD6, 0x23, 0xB);

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


//
//   Private utility functions to convert data between C++ and CX
//

IBuffer ^ConvertToIBuffer(unsigned char * buffer, unsigned int bufferLength)
{
  ArrayReference<unsigned char> a(buffer, bufferLength);

  return CryptographicBuffer::CreateFromByteArray(a);
}

ReturnValue ConvertFromIBuffer(IBuffer ^incoming, unsigned char *buffer, unsigned int &bufferLength)
{
  if (bufferLength < incoming->Length)
    return ReturnValue::BLEAPI_ERROR_BUFFER_TOO_SMALL;

  Array<unsigned char> ^a;
  CryptographicBuffer::CopyToByteArray(incoming, &a);

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
  , mNotificationsRegistered(false)
{
  //CHECK_SERVICE(mDevice, DeviceInformation);


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

  if (mLogging)
    std::cout << "   WRITE: " << bytes2ascii(buffer,
      bufferLength).c_str()
    << std::endl;

  try {
    // write characteristic
    GattCommunicationStatus status = create_task(mCharacteristicControlPoint->WriteValueAsync(b, GattWriteOption::WriteWithoutResponse)).get();
    if (status != GattCommunicationStatus::Success)
      return ReturnValue::BLEAPI_ERROR_UNKNOWN_ERROR;
  }
  catch (std::exception &e)
  {
    STRING_RUNTIME_EXCEPTION(e.what());
  }

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWinRT::ControlPointLengthRead(unsigned int * length)
{
  ReturnValue retval;
  unsigned char buffer[512];
  unsigned int bufferLength = sizeof (buffer);

  try {
    // read characteristic
    GattReadResult ^result = create_task(mCharacteristicControlPointLength->ReadValueAsync()).get();
    if (!result || (result->Status != GattCommunicationStatus::Success))
      return ReturnValue::BLEAPI_ERROR_UNKNOWN_ERROR;

    // convert to C++ data.
    retval = ConvertFromIBuffer(result->Value, buffer, bufferLength);
    if (retval)
      return retval;
  }
  catch (std::exception &e)
  {
    STRING_RUNTIME_EXCEPTION(e.what());
  }
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
  if (retval)
    return retval;

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWinRT::RegisterNotifications(pEventHandler eventHandler)
{
  ReturnValue retval = BleDevice::RegisterNotifications(eventHandler);
  if (retval != BLEAPI_ERROR_SUCCESS)
    return retval;

  if (!mNotificationsRegistered) {
    mEHWrapper = ref new BleDeviceEventhandlerWrapper(this);
    auto eh = ref new TypedEventHandler<GattCharacteristic^, GattValueChangedEventArgs^>(
      mEHWrapper, &BleDeviceEventhandlerWrapper::OnNotification
      );

    mRegistrationToken = mCharacteristicStatus->ValueChanged += eh;
    mNotificationsRegistered = true;
  }

  // check if notifications are already enabled.
  GattReadClientCharacteristicConfigurationDescriptorResult ^result = create_task(mCharacteristicStatus->ReadClientCharacteristicConfigurationDescriptorAsync()).get();
  if (result && (result->Status != GattCommunicationStatus::Success))
    return ReturnValue::BLEAPI_ERROR_UNKNOWN_ERROR;

  // if not, enable them.
  if (result->ClientCharacteristicConfigurationDescriptor != GattClientCharacteristicConfigurationDescriptorValue::Notify) {
    GattCommunicationStatus status = create_task(mCharacteristicStatus->WriteClientCharacteristicConfigurationDescriptorAsync(GattClientCharacteristicConfigurationDescriptorValue::Notify)).get();
    if (status != GattCommunicationStatus::Success)
      return ReturnValue::BLEAPI_ERROR_UNKNOWN_ERROR;
  }

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
  
  if (sender != mCharacteristicStatus)
    throw STRING_RUNTIME_EXCEPTION("Received event from unknown characteristic!");

  Array<unsigned char> ^a;
  CryptographicBuffer::CopyToByteArray(args->CharacteristicValue, &a);

  if (mLogging)
    std::cout << "   READ: " <<
    bytes2ascii
    (a->Data,
      a->Length).c_str
      ()
    << std::endl;

  // pass event to event handlers.
  EventHandler(BleDevice::EVENT_FRAGMENT, a->Data, a->Length);
}