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
  GattReadResult ^result = create_task(characteristic->ReadValueAsync()).get();
  if (result->Status != GattCommunicationStatus::Success)
    return ReturnValue::BLEAPI_ERROR_UNKNOWN_ERROR;

  // convert to C++ data.
  ReturnValue retval = ConvertFromIBuffer(result->Value, buffer, bufferLength);
  if (!retval)
    return retval;

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

  void OnAdvertisementReceived(BluetoothLEAdvertisementWatcher ^watcher, BluetoothLEAdvertisementReceivedEventArgs ^eventArgs)
  {
    mDevice->OnAdvertisementReceived(watcher, eventArgs);
  }

  void OnAdvertisementWatcherStopped(BluetoothLEAdvertisementWatcher ^watcher, BluetoothLEAdvertisementWatcherStoppedEventArgs ^eventArgs)
  {
    mDevice->OnAdvertisementWatcherStopped(watcher, eventArgs);
  }

private:
  BleDeviceWinRT *mDevice;
};


//
//  methods
//

BleDeviceWinRT::BleDeviceWinRT(pBleApi pBleApi, std::string deviceInstanceId, Windows::Devices::Bluetooth::BluetoothLEDevice ^ device, BleApiConfiguration &configuration)
  : BleDevice(configuration)
  , mDevice(device)
  , mDeviceInstanceId(deviceInstanceId)
  , mBluetoothAddress(device->BluetoothAddress)
  , mNotificationsRegistered(false)
  , mCharacteristicControlPointLength(nullptr)
  , mCharacteristicControlPoint(nullptr)
  , mCharacteristicStatus(nullptr)
  , mCharacteristicVersion(nullptr)
  , mCharacteristicVersionBitfield(nullptr)
{
  mService = mDevice->GetGattService(FIDO_SERVICE_GUID);
  if (!mService)
    STRING_RUNTIME_EXCEPTION("Could not get FIDO Service.");

  // control point length
  auto 
  characteristics =  mService->GetCharacteristics(FIDO_CHARACTERISTIC_CONTROLPOINTLENGTH_GUID);
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
  try {
    GattDeviceService ^dis = mDevice->GetGattService(GattServiceUuids::DeviceInformation);
    if (dis == nullptr)
      throw STRING_RUNTIME_EXCEPTION
      ("Could not get Device Information Service.");

    auto manufacturerNameString = dis->GetCharacteristics(GattCharacteristicUuids::ManufacturerNameString);
    if (!manufacturerNameString || (manufacturerNameString->Size < 1))
      throw STRING_RUNTIME_EXCEPTION
      ("Can't find Manufacturer Name String Characteristic in Device Information Service.");

    auto modelNumberString = dis->GetCharacteristics(GattCharacteristicUuids::ModelNumberString);
    if (!modelNumberString || (modelNumberString->Size < 1))
      throw STRING_RUNTIME_EXCEPTION
      ("Can't find Model Number String Characteristic in Device Information Service.");

    auto firmwareRevisionString = dis->GetCharacteristics(GattCharacteristicUuids::FirmwareRevisionString);
    if (!firmwareRevisionString || (firmwareRevisionString->Size < 1))
      throw STRING_RUNTIME_EXCEPTION
      ("Can't find Firmware Revision String Characteristic in Device Information Service.");

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
  catch (...) {
    throw STRING_RUNTIME_EXCEPTION("Could not find Client Characteristic Configuration Descriptor in Status Characteristic.");
  }

  if (mConfiguration.encrypt && (mDevice->DeviceInformation->Pairing->ProtectionLevel < DevicePairingProtectionLevel::Encryption))
    throw STRING_RUNTIME_EXCEPTION("Encryption is enabled but pairing protection level is too low.");

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWinRT::ControlPointWrite(unsigned char * buffer, unsigned int bufferLength)
{
  IBuffer ^b = ConvertToIBuffer(buffer, bufferLength);

  if (mConfiguration.logging & BleApiLogging::Tracing)
    std::cout << "   WRITE: " << bytes2ascii(buffer,
      bufferLength).c_str()
    << std::endl;

  try {
    // write characteristic
    GattCommunicationStatus status = create_task(mCharacteristicControlPoint->WriteValueAsync(b, GattWriteOption::WriteWithResponse)).get();
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
    if (!retval)
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
  if (!retval)
    return retval;

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleDeviceWinRT::U2FVersionBitfieldRead(unsigned char * buffer, unsigned int * bufferLength)
{
  ReturnValue retval;

  // read characteristic
  GattReadResult ^result = create_task(mCharacteristicVersionBitfield->ReadValueAsync()).get();
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
  ReturnValue retval = BleDevice::RegisterNotifications(eventHandler);
  if (!retval)
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
  if (!result || (result->Status != GattCommunicationStatus::Success))
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

    if (buffer[FIDO_BLE_VERSIONBITFIELD_VERSION_1_1_OFFSET] & FIDO_BLE_VERSIONBITFIELD_VERSION_1_1_BIT)
      return true;

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

  return true;
}

bool BleDeviceWinRT::IsConnected()
{
  return (mDevice->ConnectionStatus == BluetoothConnectionStatus::Connected);
}

bool BleDeviceWinRT::IsPaired()
{
  return (mDevice->DeviceInformation->Pairing->ProtectionLevel > DevicePairingProtectionLevel::None);
}

bool BleDeviceWinRT::IsAdvertising()
{
  return false;
}

bool BleDeviceWinRT::IsAuthenticated()
{
  return (mDevice->DeviceInformation->Pairing->ProtectionLevel == DevicePairingProtectionLevel::EncryptionAndAuthentication);
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
  BleDeviceEventhandlerWrapper    wrapper(this);

  // init for event handlers.
  mReturnAdvertisement = aAdvertisement;
  mReturnScanResponse = aScanResponse;
  mAdvReceived = mScanRespReceived = false;

  // register event handlers.
  auto advRecv = ref new TypedEventHandler<BluetoothLEAdvertisementWatcher^, BluetoothLEAdvertisementReceivedEventArgs^>(%wrapper, &BleDeviceEventhandlerWrapper::OnAdvertisementReceived);
  auto advStop = ref new TypedEventHandler<BluetoothLEAdvertisementWatcher^, BluetoothLEAdvertisementWatcherStoppedEventArgs^>(%wrapper, &BleDeviceEventhandlerWrapper::OnAdvertisementWatcherStopped);
  auto advRecvToken = watcher.Received += advRecv;
  auto advStopToken = watcher.Stopped  += advStop;

  // we want to get scan response packets.
  watcher.ScanningMode = BluetoothLEScanningMode::Active;

  // start watching.
  watcher.Start();

  // main wait. Handlers will terminate watcher if advertisement has been collected.
  while (watcher.Status == BluetoothLEAdvertisementWatcherStatus::Started)
    Sleep(100);

  // be patient.
  while (watcher.Status == BluetoothLEAdvertisementWatcherStatus::Stopping)
    Sleep(25);
  
  // cleanup
  watcher.Received -= advRecvToken;
  watcher.Stopped  -= advStopToken;
  mReturnAdvertisement = nullptr;
  mReturnScanResponse = nullptr;
  mAdvReceived = mScanRespReceived = false;

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
}

void BleDeviceWinRT::OnAdvertisementReceived(BluetoothLEAdvertisementWatcher ^watcher, BluetoothLEAdvertisementReceivedEventArgs ^eventArgs)
{
  switch (eventArgs->AdvertisementType) {
    case BluetoothLEAdvertisementType::ConnectableDirected:
    case BluetoothLEAdvertisementType::ConnectableUndirected:
    case BluetoothLEAdvertisementType::NonConnectableUndirected:
    case BluetoothLEAdvertisementType::ScannableUndirected:
      // already have it.
      if (mAdvReceived)
        return;

      // we only accept advertisements from this device.
      if (eventArgs->BluetoothAddress != mBluetoothAddress)
        return;

      // set received and record it if required.
      mAdvReceived = true;
      if (mReturnAdvertisement)
        *mReturnAdvertisement = new BleAdvertisementWinRT(eventArgs->AdvertisementType, eventArgs->Advertisement);

      break;

    case BluetoothLEAdvertisementType::ScanResponse:
      // already have it.
      if (mScanRespReceived)
        return;

      // we only accept advertisements from this device.
      if (eventArgs->BluetoothAddress != mBluetoothAddress)
        return;

      // set received and record it if required.
      mScanRespReceived = true;
      if (mReturnScanResponse)
        *mReturnScanResponse = new BleAdvertisementWinRT(eventArgs->AdvertisementType, eventArgs->Advertisement);

      break;

    default:
      return;
  }

  // always wait for an advertisement
  if (!mAdvReceived)
    return;

  // if user requested scan response data, wait for it.
  if (mReturnScanResponse && !mScanRespReceived)
    return;

  watcher->Stop();
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
    std::cout << "The operation is not supported on the current Bluetooth radio hardware.";
    break;
  default:
    std::cout << "Unknown Error";
  }
}


