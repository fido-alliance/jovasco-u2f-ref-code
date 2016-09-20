#ifndef _BLEAPI_BLEADVERTISEMENTWINRT_H_
#define _BLEAPI_BLEADVERTISEMENTWINRT_H_

#include "BleAdvertisement.h"

#include <windows.devices.bluetooth.h>

typedef class BleAdvertisementWinRT : public BleAdvertisement {
public:
  BleAdvertisementWinRT(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementType aType, Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement ^aAdv);
} *pBleAdvertisementWinRT;

#endif /* _BLEAPI_BLEADVERTISEMENTWINRT_H_ */