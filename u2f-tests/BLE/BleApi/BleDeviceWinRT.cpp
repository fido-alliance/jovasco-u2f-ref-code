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
#include <string>
#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <locale>
#include <codecvt>

#include "fido_ble.h"

#include <BleDeviceWinRT.h>
#include <BleAdvertisementWinRT.h>

using namespace Platform;
using namespace Concurrency;
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::Devices::Enumeration;
using namespace Windows::Devices::Bluetooth;
using namespace Windows::Devices::Bluetooth::GenericAttributeProfile;
using namespace Windows::Devices::Bluetooth::Advertisement;
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
#define STRING_RUNTIME_EXCEPTION(x)		std::runtime_error( __FILE__ ":" + std::to_string(__LINE__) + ": " + x)
#define CX_EXCEPTION(x)               HRESULT_RUNTIME_EXCEPTION(x->HResult)

#define CHECK_SERVICE(maDevice, maService)  try { if (maDevice->GetGattService(GattServiceUuids::maService) == nullptr) throw; } \
      catch (Platform::Exception^ comException) \
            { HRESULT_RUNTIME_EXCEPTION( comException->HResult ); } \
      catch (const std::exception& e) \
            { STRING_RUNTIME_EXCEPTION( e.what() ); } \
      catch (...) \
            { STRING_RUNTIME_EXCEPTION( "Device does not support " #maService ); } 

#define CHECK_CHARACTERISTIC_PROPERTY_SET(c, p)  if ((c->CharacteristicProperties & GattCharacteristicProperties::p) != GattCharacteristicProperties::p) throw STRING_RUNTIME_EXCEPTION(#c " does not support " #p);
#define CHECK_CHARACTERISTIC_PROPERTY_CLEAR(c, p)  if ((c->CharacteristicProperties & GattCharacteristicProperties::p) == GattCharacteristicProperties::p) throw STRING_RUNTIME_EXCEPTION(#c " must not support " #p);

static const Guid FIDO_SERVICE_GUID(0x0000FFFD, 0x0000, 0x1000, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB);
static const Guid FIDO_CHARACTERISTIC_CONTROLPOINTLENGTH_GUID(0xF1D0FFF3, 0xDEAA, 0xECEE, 0xB4, 0x2F, 0xC9, 0xBA, 0x7E, 0xD6, 0x23, 0xBB);
static const Guid FIDO_CHARACTERISTIC_CONTROLPOINT_GUID(0xF1D0FFF1, 0xDEAA, 0xECEE, 0xB4, 0x2F, 0xC9, 0xBA, 0x7E, 0xD6, 0x23, 0xBB);
static const Guid FIDO_CHARACTERISTIC_STATUS_GUID(0xF1D0FFF2, 0xDEAA, 0xECEE, 0xB4, 0x2F, 0xC9, 0xBA, 0x7E, 0xD6, 0x23, 0xBB);
static const Guid FIDO_CHARACTERISTIC_VERSION_GUID(0x00002A28, 0x0000, 0x1000, 0x80, 0x00, 0x00,0x80,0x5F, 0x9B, 0x34, 0xFB);
static const Guid FIDO_CHARACTERISTIC_VERSIONBITFIELD_GUID(0xF1D0FFF4, 0xDEAA, 0xECEE, 0xB4, 0x2F, 0xC9, 0xBA, 0x7E, 0xD6, 0x23, 0xBB);

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

std::wstring convert(std::string s)
{
  using convert_type = std::codecvt_utf8<wchar_t>;
  std::wstring_convert<convert_type, wchar_t> converter;

  return converter.from_bytes(s);
}

//
// A small function to read a characteristic to a C++ buffer
// 
ReturnValue ReadCharacteristic(GattCharacteristic ^characteristic, unsigned char *buffer, unsigned int &bufferLength)
{
  if (characteristic == nullptr)
    return ReturnValue::BLEAPI_ERROR_INVALID_PARAMETER;
  if (buffer == nullptr)
    return ReturnValue::BLEAPI_ERROR_INVALID_PARAMETER;

  // read characteristic
  GattReadResult ^result;
  try {
    result = create_task(characteristic->ReadValueAsync()).get();
    if (result->Status != GattCommunicationStatus::Success)
      return ReturnValue::BLEAPI_ERROR_UNKNOWN_ERROR;
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
    throw STRING_RUNTIME_EXCEPTION("Unknown error reading Characteristic.");
  }
  // convert to C++ data.
  ReturnValue retval = ConvertFromIBuffer(result->Value, buffer, bufferLength);
  if (!retval)
    return retval;

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue WriteCharacteristic(BleApiConfiguration &config, GattCharacteristic ^characteristic, unsigned char *buffer, unsigned int bufferLength)
{
  IBuffer ^b = ConvertToIBuffer(buffer, bufferLength);

  try {
    // write characteristic
    GattCommunicationStatus status = create_task(characteristic->WriteValueAsync(b, GattWriteOption::WriteWithResponse)).get();
    if (status != GattCommunicationStatus::Success) {
      if (config.logging & BleApiLogging::Debug)
        std::wcout << L"Error: " << status.ToString()->Data() << std::endl;
      return ReturnValue::BLEAPI_ERROR_UNKNOWN_ERROR;
    }
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
    throw STRING_RUNTIME_EXCEPTION("Unknown error writing to characteristic.");
  }

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

//
//  A small class to proxy our C++ event handler in a CX event handler.
//    you cannot pass C++ functions to CX classes.
//
ref class BleDeviceEventhandlerProxy sealed
{
internal:
  BleDeviceEventhandlerProxy(BleDeviceWinRT *dev) : mDevice(dev) {};

public:
  void OnNotification(GattCharacteristic^ sender, GattValueChangedEventArgs^ args)
  {
    mDevice->OnNotification(sender, args);
  }

  void OnAdvertisementReceived(BluetoothLEAdvertisementWatcher ^watcher, BluetoothLEAdvertisementReceivedEventArgs ^eventArgs)
  {
    mDevice->OnAdvertisementReceived(watcher, eventArgs);
  }

  void OnAdvertisementWatcherStopped(BluetoothLEAdvertisementWatcher ^watcher, BluetoothLEAdvertisementWatcherStoppedEventArgs ^eventArgs)
  {
    mDevice->OnAdvertisementWatcherStopped(watcher, eventArgs);
  }

  void OnCustomPairing(DeviceInformationCustomPairing ^pairing, DevicePairingRequestedEventArgs ^eventArgs)
  {
    mDevice->OnCustomPairing(pairing, eventArgs);
  }

private:
  BleDeviceWinRT *mDevice;
};


//
//  methods
//

void BleDeviceWinRT::Initialize()
{
  mService = mDevice->GetGattService(FIDO_SERVICE_GUID);
  if (!mService)
    STRING_RUNTIME_EXCEPTION("Could not get FIDO Service.");

  // control point length
  auto
    characteristics = mService->GetCharacteristics(FIDO_CHARACTERISTIC_CONTROLPOINTLENGTH_GUID);
  if (characteristics->Size == 0)
    throw STRING_RUNTIME_EXCEPTION("Could not find Control Point Length Characteristic in FIDO Service.");

  mCharacteristicControlPointLength = characteristics->GetAt(0);

  // control point
  characteristics = mService->GetCharacteristics(FIDO_CHARACTERISTIC_CONTROLPOINT_GUID);
  if (characteristics->Size == 0)
    throw STRING_RUNTIME_EXCEPTION("Could not find Control Point Characteristic in FIDO Service.");

  mCharacteristicControlPoint = characteristics->GetAt(0);

  // status
  characteristics = mService->GetCharacteristics(FIDO_CHARACTERISTIC_STATUS_GUID);
  if (characteristics->Size == 0)
    throw STRING_RUNTIME_EXCEPTION("Could not find Status Characteristic in FIDO Service.");

  mCharacteristicStatus = characteristics->GetAt(0);

  // version
  bool v10version = false, v11version = false;
  characteristics = mService->GetCharacteristics(FIDO_CHARACTERISTIC_VERSION_GUID);
  if (characteristics->Size > 0)
    mCharacteristicVersion = characteristics->GetAt(0);

  characteristics = mService->GetCharacteristics(FIDO_CHARACTERISTIC_VERSIONBITFIELD_GUID);
  if (characteristics->Size > 0)
    mCharacteristicVersionBitfield = characteristics->GetAt(0);
}

BleDeviceWinRT::BleDeviceWinRT(pBleApi pBleApi, std::string deviceInstanceId, Windows::Devices::Bluetooth::BluetoothLEDevice ^ device, BleApiConfiguration &configuration)
  : BleDevice(configuration)
  , mDevice(device)
  , mDeviceInstanceId(deviceInstanceId)
  , mBluetoothAddress(device->BluetoothAddress)
  , mNotificationsRegistered(false)
  , mService(nullptr)
  , mCharacteristicControlPointLength(nullptr)
  , mCharacteristicControlPoint(nullptr)
  , mCharacteristicStatus(nullptr)
  , mCharacteristicVersion(nullptr)
  , mCharacteristicVersionBitfield(nullptr)
{
  // fetch all internally used pointers.
  Initialize();

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

ReturnValue BleDeviceWinRT::Verify()
{
  if (mDevice == nullptr)
    throw STRING_RUNTIME_EXCEPTION("Device not initialized.");
  
  try {
    GattDeviceService ^dis = mDevice->GetGattService(GattServiceUuids::DeviceInformation);
    if (dis == nullptr)
      throw STRING_RUNTIME_EXCEPTION
      ("Could not get Device Information Service.");

    auto manufacturerNameString = dis->GetCharacteristics(GattCharacteristicUuids::ManufacturerNameString);
    if (!manufacturerNameString || (manufacturerNameString->Size < 1))
      throw STRING_RUNTIME_EXCEPTION
      ("Can't find Manufacturer Name String Characteristic in Device Information Service.");

    // https://www.bluetooth.com/specifications/gatt/viewer?attributeXmlFile=org.bluetooth.service.device_information.xml
    CHECK_CHARACTERISTIC_PROPERTY_SET(manufacturerNameString->GetAt(0), Read);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(manufacturerNameString->GetAt(0), Write);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(manufacturerNameString->GetAt(0), WriteWithoutResponse);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(manufacturerNameString->GetAt(0), AuthenticatedSignedWrites);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(manufacturerNameString->GetAt(0), Notify);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(manufacturerNameString->GetAt(0), Indicate);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(manufacturerNameString->GetAt(0), WritableAuxiliaries);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(manufacturerNameString->GetAt(0), Broadcast);

    auto modelNumberString = dis->GetCharacteristics(GattCharacteristicUuids::ModelNumberString);
    if (!modelNumberString || (modelNumberString->Size < 1))
      throw STRING_RUNTIME_EXCEPTION
      ("Can't find Model Number String Characteristic in Device Information Service.");

    // https://www.bluetooth.com/specifications/gatt/viewer?attributeXmlFile=org.bluetooth.service.device_information.xml
    CHECK_CHARACTERISTIC_PROPERTY_SET(modelNumberString->GetAt(0), Read);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(modelNumberString->GetAt(0), Write);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(modelNumberString->GetAt(0), WriteWithoutResponse);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(modelNumberString->GetAt(0), AuthenticatedSignedWrites);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(modelNumberString->GetAt(0), Notify);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(modelNumberString->GetAt(0), Indicate);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(modelNumberString->GetAt(0), WritableAuxiliaries);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(modelNumberString->GetAt(0), Broadcast);

    auto firmwareRevisionString = dis->GetCharacteristics(GattCharacteristicUuids::FirmwareRevisionString);
    if (!firmwareRevisionString || (firmwareRevisionString->Size < 1))
      throw STRING_RUNTIME_EXCEPTION
      ("Can't find Firmware Revision String Characteristic in Device Information Service.");

    // https://www.bluetooth.com/specifications/gatt/viewer?attributeXmlFile=org.bluetooth.service.device_information.xml
    CHECK_CHARACTERISTIC_PROPERTY_SET(firmwareRevisionString->GetAt(0), Read);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(firmwareRevisionString->GetAt(0), Write);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(firmwareRevisionString->GetAt(0), WriteWithoutResponse);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(firmwareRevisionString->GetAt(0), AuthenticatedSignedWrites);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(firmwareRevisionString->GetAt(0), Notify);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(firmwareRevisionString->GetAt(0), Indicate);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(firmwareRevisionString->GetAt(0), WritableAuxiliaries);
    CHECK_CHARACTERISTIC_PROPERTY_CLEAR(firmwareRevisionString->GetAt(0), Broadcast);
  }
  catch (std::runtime_error &e) {
    throw e;
  }
  catch (...) {
    STRING_RUNTIME_EXCEPTION("Error checking Device Information Service.");
  }

  CHECK_CHARACTERISTIC_PROPERTY_SET(mCharacteristicControlPointLength, Read);
  CHECK_CHARACTERISTIC_PROPERTY_SET(mCharacteristicControlPoint, Write);
  CHECK_CHARACTERISTIC_PROPERTY_SET(mCharacteristicStatus, Notify);

  bool v10version(false), v11version(false);
  if (mCharacteristicVersion != nullptr) {
    CHECK_CHARACTERISTIC_PROPERTY_SET(mCharacteristicVersion, Read);
    v10version = true;
  }

  if (mCharacteristicVersionBitfield != nullptr) {
    CHECK_CHARACTERISTIC_PROPERTY_SET(mCharacteristicVersionBitfield, Read);
    CHECK_CHARACTERISTIC_PROPERTY_SET(mCharacteristicVersionBitfield, Write);
    v11version = true;
  }

  if (!v10version && !v11version)
    throw STRING_RUNTIME_EXCEPTION("Could not find Version or VersionBitfield Characteristic in FIDO Service.");

  if ((mConfiguration.version == U2FVersion::V1_0) && !v10version)
    throw STRING_RUNTIME_EXCEPTION("U2F Version is 1.0 and could not find Version Characteristic in FIDO Service.");

  if ((mConfiguration.version == U2FVersion::V1_1) && !v11version)
    throw STRING_RUNTIME_EXCEPTION("U2F Version is 1.1 and could not find VersionBitfield Characteristic in FIDO Service.");

  // check CCC is present
  try {
    GattReadClientCharacteristicConfigurationDescriptorResult ^result = create_task(mCharacteristicStatus->ReadClientCharacteristicConfigurationDescriptorAsync()).get();
    if (!result || (result->Status != GattCommunicationStatus::Success))
      throw;
  }
  catch (std::exception &e)
  {
    throw STRING_RUNTIME_EXCEPTION(e.what());
  }
  catch (Exception ^e)
  {
    throw CX_EXCEPTION(e);
  }
  catch (...) {
    throw STRING_RUNTIME_EXCEPTION("Could not find Client Characteristic Configuration Descriptor in Status Characteristic.");
  }

  if (mConfiguration.encrypt && (mDevice->DeviceInformation->Pairing->ProtectionLevel < DevicePairingProtectionLevel::Encryption))
    throw STRING_RUNTIME_EXCEPTION("Encryption is enabled but pairing protection level is too low.");

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWinRT::ControlPointWrite(unsigned char * buffer, unsigned int bufferLength)
{
  if ((mDevice == nullptr)||(mCharacteristicControlPoint == nullptr))
    throw STRING_RUNTIME_EXCEPTION("Device not initialized.");

  if (mConfiguration.logging & BleApiLogging::Tracing)
    std::cout << "   WRITE: " << bytes2ascii(buffer, bufferLength).c_str() << std::endl;

  ReturnValue retval = WriteCharacteristic(mConfiguration, mCharacteristicControlPoint, buffer, bufferLength);
  if (!retval)
    return retval;

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWinRT::ControlPointLengthRead(unsigned int * length)
{
  if ((mDevice == nullptr)||(mCharacteristicControlPointLength == nullptr))
    throw STRING_RUNTIME_EXCEPTION("Device not initialized.");

  ReturnValue retval;
  unsigned char buffer[512];
  unsigned int bufferLength = sizeof (buffer);

  retval = ReadCharacteristic(mCharacteristicControlPointLength, buffer, bufferLength);
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
  if ((mDevice == nullptr)||(mCharacteristicVersion == nullptr))
    throw STRING_RUNTIME_EXCEPTION("Device not initialized.");

  ReturnValue 
  retval = ReadCharacteristic(mCharacteristicVersion, buffer, *bufferLength);
  if (!retval)
    return retval;

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWinRT::U2FVersionBitfieldRead(unsigned char * buffer, unsigned int * bufferLength)
{
  if ((mDevice == nullptr)||(mCharacteristicVersionBitfield == nullptr))
    throw STRING_RUNTIME_EXCEPTION("Device not initialized.");

  ReturnValue
  retval = ReadCharacteristic(mCharacteristicVersionBitfield, buffer, *bufferLength);
  if (!retval)
    return retval;

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWinRT::U2FVersionBitfieldWrite(unsigned char * buffer, unsigned int * bufferLength)
{
  if ((mDevice == nullptr) || (mCharacteristicVersionBitfield == nullptr))
    throw STRING_RUNTIME_EXCEPTION("Device not initialized.");

  if (mConfiguration.logging & BleApiLogging::Tracing)
    std::cout << "   WRITE: " << bytes2ascii(buffer, *bufferLength).c_str() << std::endl;

  ReturnValue retval = WriteCharacteristic(mConfiguration, mCharacteristicControlPoint, buffer, *bufferLength);
  if (!retval)
    return retval;

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}


ReturnValue BleDeviceWinRT::RegisterNotifications(pEventHandler eventHandler)
{
  if ((mDevice == nullptr)||(mCharacteristicStatus == nullptr))
    throw STRING_RUNTIME_EXCEPTION("Device not initialized.");

  ReturnValue retval = BleDevice::RegisterNotifications(eventHandler);
  if (!retval)
    return retval;

  if (!mNotificationsRegistered) {
    mNotificationProxy = ref new BleDeviceEventhandlerProxy(this);
    auto eh = ref new TypedEventHandler<GattCharacteristic^, GattValueChangedEventArgs^>(
      mNotificationProxy, &BleDeviceEventhandlerProxy::OnNotification
      );

    mRegistrationToken = mCharacteristicStatus->ValueChanged += eh;
    mNotificationsRegistered = true;
  }

  // check if notifications are already enabled.
  GattReadClientCharacteristicConfigurationDescriptorResult ^result;
  try {
    result = create_task(mCharacteristicStatus->ReadClientCharacteristicConfigurationDescriptorAsync()).get();
    if (!result || (result->Status != GattCommunicationStatus::Success))
      return ReturnValue::BLEAPI_ERROR_UNKNOWN_ERROR;
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
    throw STRING_RUNTIME_EXCEPTION("Unknown error reading Client Characteristic Configuration Descriptor");
  }

  // if not, enable them.
  if (result->ClientCharacteristicConfigurationDescriptor != GattClientCharacteristicConfigurationDescriptorValue::Notify) {
    try {
    GattCommunicationStatus status = create_task(mCharacteristicStatus->WriteClientCharacteristicConfigurationDescriptorAsync(GattClientCharacteristicConfigurationDescriptorValue::Notify)).get();
    if (status != GattCommunicationStatus::Success)
      return ReturnValue::BLEAPI_ERROR_UNKNOWN_ERROR;
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
      throw STRING_RUNTIME_EXCEPTION("Unknown error writing Client Characteristic Configuration Descriptor");
    }
  }

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWinRT::Sleep(unsigned int miliseconds)
{
  ::Sleep(miliseconds);

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

uint64_t BleDeviceWinRT::TimeMs()
{
  return (uint64_t)GetTickCount64();
}

std::string BleDeviceWinRT::Identifier()
{
  return mDeviceInstanceId;
}

bool BleDeviceWinRT::SupportsVersion(U2FVersion version)
{
  unsigned char buffer[512];
  unsigned int bufferLength(sizeof(buffer));

  // no bitfield characteristic.
  if (version == U2FVersion::V1_0)
    return mSupportsVersion_1_0;

  // cached.
  if ((version == U2FVersion::V1_1) && mSupportsVersion_1_1)
    return mSupportsVersion_1_1;

  // check the bitfield characteristic.
  ReturnValue retval = U2FVersionBitfieldRead(buffer, &bufferLength);
  if (retval != ReturnValue::BLEAPI_ERROR_SUCCESS)
    throw STRING_RUNTIME_EXCEPTION("Could not read U2FVersionBitField characteristic.");

  // must be at least 1 byte if not, characteristic must be omitted.
  if (bufferLength < 1)
    throw STRING_RUNTIME_EXCEPTION("Could not read at least 1 byte from U2FVersionBitField characteristic.");

  // verify 0 bytes are omitted.
  if ((buffer[bufferLength - 1] == 0))
    throw STRING_RUNTIME_EXCEPTION("U2FVersionBitField characteristic ends in 0 byte, byte must be omitted.");

  // check version bits
  switch (version) {
  case U2FVersion::V1_1:
    if (bufferLength < FIDO_BLE_VERSIONBITFIELD_VERSION_1_1_OFFSET)
      return false;

    if (buffer[FIDO_BLE_VERSIONBITFIELD_VERSION_1_1_OFFSET] & FIDO_BLE_VERSIONBITFIELD_VERSION_1_1_BIT) {
      mSupportsVersion_1_1 = true;
      return true;
    }

    return false;
  default:
    return false;
  }

  return false;
}

bool BleDeviceWinRT::SelectVersion(U2FVersion version, bool force)
{
  // if 1.0 is supported, this is the default version.
  if (mSupportsVersion_1_0 && (version == U2FVersion::V1_0))
    return true;

  // check if we support the version we want to select, unless we are forcing a write.
  if (!force && !SupportsVersion(version))
    return false;
  
  // now we write the characteristic.
  // FIXME

  return true;
}

bool BleDeviceWinRT::IsConnected()
{
  if (mDevice == nullptr)
    return false;

  return (mDevice->ConnectionStatus == BluetoothConnectionStatus::Connected);
}

bool BleDeviceWinRT::IsPaired()
{
  if (mDevice == nullptr)
    return false;

  return (mDevice->DeviceInformation->Pairing->ProtectionLevel > DevicePairingProtectionLevel::None);
}

bool BleDeviceWinRT::IsAdvertising()
{
  if (mDevice == nullptr)
    throw STRING_RUNTIME_EXCEPTION("Device not initialized.");

  return false;
}

bool BleDeviceWinRT::IsAuthenticated()
{
  if (mDevice == nullptr)
    throw STRING_RUNTIME_EXCEPTION("Device not initialized.");

  return (mDevice->DeviceInformation->Pairing->ProtectionLevel == DevicePairingProtectionLevel::EncryptionAndAuthentication);
}

ReturnValue BleDeviceWinRT::Unpair()
{
  if ((mDevice == nullptr) || !mDevice->DeviceInformation->Pairing->IsPaired)
    return ReturnValue::BLEAPI_ERROR_SUCCESS;

  if (mNotificationsRegistered) {
    mCharacteristicStatus->ValueChanged -= mRegistrationToken;
    mNotificationsRegistered = false;
    mNotificationProxy = nullptr;
  }

  DeviceUnpairingResult ^result;
  try {
    result = create_task(mDevice->DeviceInformation->Pairing->UnpairAsync()).get();
    if (result->Status != DeviceUnpairingResultStatus::Unpaired)
      return ReturnValue::BLEAPI_ERROR_UNKNOWN_ERROR;
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
    throw STRING_RUNTIME_EXCEPTION("Unknown error unpairing.");
  }

  mDevice = nullptr;
  mService = nullptr;
  mCharacteristicControlPointLength = nullptr;
  mCharacteristicControlPoint = nullptr;
  mCharacteristicStatus = nullptr;
  mCharacteristicVersion = nullptr;
  mCharacteristicVersionBitfield = nullptr;

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWinRT::Pair()
{
  if ((mDevice != nullptr) && mDevice->DeviceInformation->Pairing->IsPaired)
    return ReturnValue::BLEAPI_ERROR_SUCCESS;

  if (mDevice == nullptr) {
    mDevice = create_task(BluetoothLEDevice::FromBluetoothAddressAsync(mBluetoothAddress)).get();
    if (!mDevice)
      return ReturnValue::BLEAPI_ERROR_UNKNOWN_ERROR;
  }

  // register event handler
  BleDeviceEventhandlerProxy    wrapper(this);
  auto pairingEventHandler = ref new TypedEventHandler<DeviceInformationCustomPairing^, DevicePairingRequestedEventArgs^>(%wrapper, &BleDeviceEventhandlerProxy::OnCustomPairing);
  auto pairingToken = mDevice->DeviceInformation->Pairing->Custom->PairingRequested += pairingEventHandler;

  // wait until we detect the device
  WaitForDevice();

  DevicePairingResult ^result;
  
  try {
    result = create_task(mDevice->DeviceInformation->Pairing->Custom->PairAsync(
      // support all pairing kinds.
      DevicePairingKinds::ConfirmOnly | DevicePairingKinds::ConfirmPinMatch | DevicePairingKinds::DisplayPin | DevicePairingKinds::ProvidePin,
      // require encryption as configured.
      mConfiguration.encrypt ? DevicePairingProtectionLevel::Encryption : DevicePairingProtectionLevel::None
    )).get();
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

  if (result->Status != DevicePairingResultStatus::Paired) {
    if ((mConfiguration.logging & BleApiLogging::Debug) != 0)
      std::wcout << L"Pairing failed with: " << result->Status.ToString()->Data() << std::endl;
    mDevice->DeviceInformation->Pairing->Custom->PairingRequested -= pairingToken;
    mDevice = nullptr;
    return ReturnValue::BLEAPI_ERROR_UNKNOWN_ERROR;
  }

  // clean up event handler.
  mDevice->DeviceInformation->Pairing->Custom->PairingRequested -= pairingToken;

  // now we have successfully paired, recover the device and all relevant points.
  String ^id = ref new String(convert(mDeviceInstanceId).c_str());

  if ((mConfiguration.logging & BleApiLogging::Debug) != 0)
    std::cout << "Waiting until device discovery is complete." << std::endl;

  // this mess is necessary because we can detect the device and the service before
  //   full device discovery is completed.
  do {
    // clean up.
    if (mDevice != nullptr) {
      mDevice = nullptr;
    }

    // Give Windows some time.
    Sleep(250);

    // fetch device
    try {
      mDevice = create_task(BluetoothLEDevice::FromIdAsync(id)).get();
    }
    catch (...) {
      mDevice = nullptr;
    };

    // if successfull, try to initialize our object again.
    if (mDevice != nullptr) {
      try {
        Initialize();
      }
      catch (...) {
        // not fully initialized, so clean up.
        mService = nullptr;
        mCharacteristicControlPointLength = nullptr;
        mCharacteristicControlPoint = nullptr;
        mCharacteristicStatus = nullptr;
        mCharacteristicVersion = nullptr;
        mCharacteristicVersionBitfield = nullptr;
      };

      if (mService != nullptr)
        break;
    }
  } while (true);

  // wait until device disconnects after pairing.
  std::cout << "Waiting until device disconnects." << std::endl;
  while (IsConnected()) 
     Sleep(250);

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

void BleDeviceWinRT::Report()
{
  std::wcout << L"Device Display Name: " << mDevice->Name->Data() << std::endl;
  std::wcout << L"Device Identifier  : " << mDevice->DeviceId->Data() << std::endl;

  uint64_t address = mDevice->BluetoothAddress;
  std::wcout << L"Bluetooth Address  : " << std::hex << std::setfill(L'0');
  for (unsigned int i = 0; i < 6; i++) {
    std::wcout << std::setw(2)  << ((address >> (5 - i) * 8) & 0x000000FF);
    if (i < 5)
      std::wcout << ":";
  }
  std::wcout << std::dec << std::setfill(L' ') << std::endl;

  unsigned char buffer[512];
  unsigned int bufferLength;
  GattDeviceService ^dis;
  
  try {
    dis = mDevice->GetGattService(GattServiceUuids::DeviceInformation);
    if (dis != nullptr)
      return;

    auto manufacturerNameString = dis->GetCharacteristics(GattCharacteristicUuids::ManufacturerNameString);
    if (manufacturerNameString && (manufacturerNameString->Size > 0)) {
      bufferLength = sizeof(buffer);
      if (ReadCharacteristic(manufacturerNameString->GetAt(0), buffer, bufferLength) == ReturnValue::BLEAPI_ERROR_SUCCESS)
        std::cout << "Manufacturer Name  : " << std::string((char *)buffer, bufferLength) << std::endl;
    }

    auto modelNumberString = dis->GetCharacteristics(GattCharacteristicUuids::ModelNumberString);
    if (!modelNumberString || (modelNumberString->Size > 0)) {
      bufferLength = sizeof(buffer);
      if (ReadCharacteristic(modelNumberString->GetAt(0), buffer, bufferLength) == ReturnValue::BLEAPI_ERROR_SUCCESS)
        std::cout << "Model Number       : " << std::string((char *)buffer, bufferLength) << std::endl;
    }
    auto firmwareRevisionString = dis->GetCharacteristics(GattCharacteristicUuids::FirmwareRevisionString);
    if (!firmwareRevisionString || (firmwareRevisionString->Size > 0)) {
      bufferLength = sizeof(buffer);
      if (ReadCharacteristic(firmwareRevisionString->GetAt(0), buffer, bufferLength) == ReturnValue::BLEAPI_ERROR_SUCCESS)
        std::cout << "Firmware Revision  : " << std::string((char *)buffer, bufferLength) << std::endl;
    }
  } catch (...) {
    if (!dis && (mConfiguration.version == U2FVersion::V1_1))
      throw STRING_RUNTIME_EXCEPTION("Could not read Device Information Service.");
  }
}

ReturnValue BleDeviceWinRT::WaitForDevice(BleAdvertisement **aAdvertisement, BleAdvertisement **aScanResponse)
{
  BluetoothLEAdvertisementWatcher watcher;
  BleDeviceEventhandlerProxy    wrapper(this);

  Lock();

  // init for event handlers.
  mReturnAdvertisement = aAdvertisement;
  mReturnScanResponse = aScanResponse;
  mAdvReceived = mScanRespReceived = mDetectOnly = false;
  mAutoStop = true;

  // register event handlers.
  auto advRecv = ref new TypedEventHandler<BluetoothLEAdvertisementWatcher^, BluetoothLEAdvertisementReceivedEventArgs^>(%wrapper, &BleDeviceEventhandlerProxy::OnAdvertisementReceived);
  auto advStop = ref new TypedEventHandler<BluetoothLEAdvertisementWatcher^, BluetoothLEAdvertisementWatcherStoppedEventArgs^>(%wrapper, &BleDeviceEventhandlerProxy::OnAdvertisementWatcherStopped);
  auto advRecvToken = watcher.Received += advRecv;
  auto advStopToken = watcher.Stopped  += advStop;

  // we want to get scan response packets.
  watcher.ScanningMode = BluetoothLEScanningMode::Active;

  // start watching.
  watcher.Start();

  // main wait. Handlers will terminate watcher if advertisement has been collected.
  while (watcher.Status == BluetoothLEAdvertisementWatcherStatus::Started) {
    UnLock();
    Sleep(100);
    Lock();
  }

  // be patient.
  while (watcher.Status == BluetoothLEAdvertisementWatcherStatus::Stopping) {
    UnLock();
    Sleep(25);
    Lock();
  }

  // cleanup
  watcher.Received -= advRecvToken;
  watcher.Stopped  -= advStopToken;
  mReturnAdvertisement = nullptr;
  mReturnScanResponse = nullptr;
  mAdvReceived = mScanRespReceived = false;

  UnLock();

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWinRT::WaitForAdvertisementStop()
{
  uint64_t localCount;
  BluetoothLEAdvertisementWatcher watcher;
  BleDeviceEventhandlerProxy    wrapper(this);

  Lock();

  // init for event handlers.
  mReturnAdvertisement = nullptr;
  mReturnScanResponse = nullptr;
  mAdvReceived = mScanRespReceived = false;
  mDetectOnly = true;
  mAutoStop = false;
  mAdvCount = localCount = 0;
  
  // register event handlers.
  auto advRecv = ref new TypedEventHandler<BluetoothLEAdvertisementWatcher^, BluetoothLEAdvertisementReceivedEventArgs^>(%wrapper, &BleDeviceEventhandlerProxy::OnAdvertisementReceived);
  auto advStop = ref new TypedEventHandler<BluetoothLEAdvertisementWatcher^, BluetoothLEAdvertisementWatcherStoppedEventArgs^>(%wrapper, &BleDeviceEventhandlerProxy::OnAdvertisementWatcherStopped);
  auto advRecvToken = watcher.Received += advRecv;
  auto advStopToken = watcher.Stopped += advStop;

  // we want to get scan response packets.
  watcher.ScanningMode = BluetoothLEScanningMode::Active;

  // start watching.
  watcher.Start();

  // main wait. will terminate if no advertisements have been seen for 1s
  uint64_t t = TimeMs();
  while ((watcher.Status == BluetoothLEAdvertisementWatcherStatus::Started) && ( (TimeMs() - t) < 1000)) {
    // record last advertisement count.
    localCount = mAdvCount;

    // go to sleep.
    UnLock();
    Sleep(100);
    Lock();

    // adv detected in last sleep?
    if (localCount != mAdvCount)
      t = TimeMs();
  }

  // stop watching.
  watcher.Stop();

  // cleanup
  watcher.Received -= advRecvToken;
  watcher.Stopped -= advStopToken;
  mReturnAdvertisement = nullptr;
  mReturnScanResponse = nullptr;
  mAdvReceived = mScanRespReceived = false;
  mDetectOnly = false;
  mAdvCount = 0;

  UnLock();

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWinRT::WaitForAdvertisement(bool withPairingMode)
{
  BleAdvertisement *advertisement;
  BluetoothLEAdvertisementWatcher watcher;
  BleDeviceEventhandlerProxy    wrapper(this);

  Lock();
  try {
    // init for event handlers.
    mReturnAdvertisement = &advertisement;
    mReturnScanResponse = nullptr;
    mAdvReceived = mScanRespReceived = false;
    mDetectOnly = false; mAutoStop = false;
    mAdvCount = 0;

    // register event handlers.
    auto advRecv = ref new TypedEventHandler<BluetoothLEAdvertisementWatcher^, BluetoothLEAdvertisementReceivedEventArgs^>(%wrapper, &BleDeviceEventhandlerProxy::OnAdvertisementReceived);
    auto advStop = ref new TypedEventHandler<BluetoothLEAdvertisementWatcher^, BluetoothLEAdvertisementWatcherStoppedEventArgs^>(%wrapper, &BleDeviceEventhandlerProxy::OnAdvertisementWatcherStopped);
    auto advRecvToken = watcher.Received += advRecv;
    auto advStopToken = watcher.Stopped += advStop;

    // we want to get scan response packets.
    watcher.ScanningMode = BluetoothLEScanningMode::Active;

    // start watching.
    watcher.Start();

    // main wait. will terminate if no advertisements have been seen for 1s
    do {
      do {
        // go to sleep.
        UnLock();
        Sleep(100);
        Lock();
      } while (!mAdvReceived);

      // check flags
      const auto flags = advertisement->GetSection(BleAdvertisementSectionType::Flags);

      // if one of those flags is on, it is a pairing mode advertisement.
      if (((flags[0] & (BleFlagFields::LEGeneralDiscoverabilityMode | BleFlagFields::LELimitedDiscoverabilityMode)) != 0) == withPairingMode)
        break;

      advertisement = nullptr;
      mAdvReceived = false;
    } while (true);

    // stop watching.
    watcher.Stop();
    while (watcher.Status == BluetoothLEAdvertisementWatcherStatus::Stopping)
      Sleep(25);

    // cleanup
    watcher.Received -= advRecvToken;
    watcher.Stopped -= advStopToken;
    mReturnAdvertisement = nullptr;
    mReturnScanResponse = nullptr;
    mAdvReceived = mScanRespReceived = false;
    mDetectOnly = false;
    mAdvCount = 0;
  }
  catch (...) {

  }
  UnLock();

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
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

  Lock();

  Array<unsigned char> ^a;
  CryptographicBuffer::CopyToByteArray(args->CharacteristicValue, &a);

  if (mConfiguration.logging & BleApiLogging::Tracing)
    std::cout << "   READ: " <<
    bytes2ascii
    (a->Data,
      a->Length).c_str
      ()
    << std::endl;

  // pass event to event handlers.
  EventHandler(BleDevice::EVENT_FRAGMENT, a->Data, a->Length);

  UnLock();
}

void BleDeviceWinRT::OnAdvertisementReceived(BluetoothLEAdvertisementWatcher ^watcher, BluetoothLEAdvertisementReceivedEventArgs ^eventArgs)
{
  Lock();
  try {
    // we are only waiting for the advertising to stop. no need for detailed processing.
    if (mDetectOnly) {
      if (eventArgs->BluetoothAddress == mBluetoothAddress)
        mAdvCount++;

      UnLock();
      return;
    }

    // we are capturing adv and possibly scan response packets.
    switch (eventArgs->AdvertisementType) {
    case BluetoothLEAdvertisementType::ConnectableDirected:
    case BluetoothLEAdvertisementType::ConnectableUndirected:
    case BluetoothLEAdvertisementType::NonConnectableUndirected:
    case BluetoothLEAdvertisementType::ScannableUndirected:
      // already have it.
      if (mAdvReceived) {
        UnLock();
        return;
      }

      // we only accept advertisements from this device.
      if (eventArgs->BluetoothAddress != mBluetoothAddress) {
        UnLock();
        return;
      }

      // set received and record it if required.
      mAdvReceived = true;
      if (mReturnAdvertisement)
        *mReturnAdvertisement = new BleAdvertisementWinRT(eventArgs->AdvertisementType, eventArgs->Advertisement);

      if (mDevice == nullptr) {
        mDevice = create_task(BluetoothLEDevice::FromBluetoothAddressAsync(mBluetoothAddress)).get();
        if (mDevice == nullptr) {
          UnLock();
          return;
        }
      }

      break;

    case BluetoothLEAdvertisementType::ScanResponse:
      // already have it.
      if (mScanRespReceived) {
        UnLock();
        return;
      }

      // we only accept advertisements from this device.
      if (eventArgs->BluetoothAddress != mBluetoothAddress) {
        UnLock();
        return;
      }

      // set received and record it if required.
      mScanRespReceived = true;
      if (mReturnScanResponse)
        *mReturnScanResponse = new BleAdvertisementWinRT(eventArgs->AdvertisementType, eventArgs->Advertisement);

      break;

    default:
      UnLock();
      return;
    }

    // always wait for an advertisement
    if (!mAdvReceived) {
      UnLock();
      return;
    }

    // if user requested scan response data, wait for it.
    if (mReturnScanResponse && !mScanRespReceived) {
      UnLock();
      return;
    }

    if (mAutoStop)
      watcher->Stop();

  }
  catch (...) {};

  UnLock();
}

void BleDeviceWinRT::OnAdvertisementWatcherStopped(BluetoothLEAdvertisementWatcher ^watcher, BluetoothLEAdvertisementWatcherStoppedEventArgs ^eventArgs)
{
  if (eventArgs->Error == BluetoothError::Success)
    return;

  std::cout << "Bluetooth error ";
  switch (eventArgs->Error)
  {
  case BluetoothError::RadioNotAvailable:
    std::cout << "The Bluetooth radio was not available. This error occurs when the Bluetooth radio has been turned off.";
    break;
  case BluetoothError::ResourceInUse:
    std::cout << "The operation cannot be serviced because the necessary resources are currently in use.";
    break;
  case BluetoothError::DeviceNotConnected:
    std::cout << "The operation cannot be completed because the remote device is not connected.";
    break;
  case BluetoothError::OtherError:
    std::cout << "An unexpected error has occurred.";
    break;
  case BluetoothError::DisabledByPolicy:
    std::cout << "The operation is disabled by policy.";
    break;
  case BluetoothError::NotSupported:
    std::cout << "The operation is not supported on the current Bluetooth radio hardware.";
    break;
  case BluetoothError::DisabledByUser:
    std::cout << "The operation is disabled by the user.";
    break;
  case BluetoothError::ConsentRequired:
    std::cout << "The operation requires consent.";
    break;
  default:
    std::cout << "Unknown Error";
  }
}

void BleDeviceWinRT::OnCustomPairing(Windows::Devices::Enumeration::DeviceInformationCustomPairing ^ pairing, Windows::Devices::Enumeration::DevicePairingRequestedEventArgs ^ eventArgs)
{
  if (mConfiguration.logging & BleApiLogging::Debug)
    std::wcout << L"OnCustomPairing called for " << eventArgs->DeviceInformation->Name->Data() << L" with " << eventArgs->PairingKind.ToString()->Data() << std::endl;

  
  switch (eventArgs->PairingKind)
  {
  case DevicePairingKinds::ConfirmOnly:
    eventArgs->Accept();
    break;
  case DevicePairingKinds::ConfirmPinMatch:
  case DevicePairingKinds::DisplayPin:
    std::wcout << L"Pairing PIN is: " << eventArgs->Pin->Data() << std::endl;
    eventArgs->Accept();
    break;
  case DevicePairingKinds::ProvidePin:
  {
    String ^pin = ref new String(convert(mConfiguration.pin).c_str());
    if (pin != nullptr) {
      eventArgs->Accept(pin);
    } else {
      std::cout << "Pairing required PIN but it not supplied." << std::endl << std::flush;
    }
    break;
  }
  default:
    break;
    //throw std::exception("Not Implemented.");
  }
}


