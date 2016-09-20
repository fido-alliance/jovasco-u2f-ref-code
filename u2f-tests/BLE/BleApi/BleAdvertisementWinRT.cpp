#include "BleAdvertisementWinRT.h"

#include "collection.h"
#include "BleApiError.h"

using namespace Platform;
using namespace Windows::Devices::Bluetooth;
using namespace Windows::Devices::Bluetooth::Advertisement;
using namespace Windows::Foundation::Collections;
using namespace Windows::Storage::Streams;
using namespace Windows::Security::Cryptography;

ReturnValue ConvertFromIBuffer(IBuffer ^incoming, std::vector<unsigned char> &buffer)
{
  Array<unsigned char> ^a;
  CryptographicBuffer::CopyToByteArray(incoming, &a);

  buffer.resize(a->Length);
  memcpy(buffer.data(), a->Data, a->Length);

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

BleAdvertisementWinRT::BleAdvertisementWinRT(BluetoothLEAdvertisementType aType, BluetoothLEAdvertisement ^aAdv)
  : BleAdvertisement( (aType != BluetoothLEAdvertisementType::ScanResponse) ? BleAdvertisementType::Advertisement : BleAdvertisementType::ScanResponse)
{
  IVector<BluetoothLEAdvertisementDataSection ^> ^sections = aAdv->DataSections;
  
  std::for_each(begin(sections), end(sections), [&](BluetoothLEAdvertisementDataSection ^section) {
    std::vector<unsigned char> buffer;
    ConvertFromIBuffer(section->Data, buffer);

    mSections.emplace(std::make_pair(static_cast<BleAdvertisementSectionType>(section->DataType), buffer));
  });
}
