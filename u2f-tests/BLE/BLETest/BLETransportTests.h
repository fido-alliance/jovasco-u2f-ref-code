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

#ifndef _BLETRANSPORTTESTS_H_
#define _BLETRANSPORTTESTS_H_

#include "BleApi.h"

extern void BleApiTest_TransportEventHandler(BleDevice::FIDOEventType type,
					     unsigned char *buffer,
					     unsigned int bufferLength);

extern ReturnValue BleApiTest_TransportPing(pBleDevice dev);
extern ReturnValue BleApiTest_TransportLongPing(pBleDevice dev);
extern ReturnValue BleApiTest_TransportLimits(pBleDevice dev);
extern ReturnValue BleApiTest_TransportUnknown(pBleDevice dev,
					       unsigned char cmd);
extern ReturnValue BleApiTest_TransportNotCont(pBleDevice dev);
extern ReturnValue BleApiTest_TransportBadSequence(pBleDevice dev);
extern ReturnValue BleApiTest_TransportContFirst(pBleDevice dev);
extern ReturnValue BleApiTest_TransportTooLong(pBleDevice dev);
extern ReturnValue BleApiTest_AdvertisingNotPairingMode(pBleDevice dev);
extern ReturnValue BleApiTest_AdvertisingPairingMode(pBleDevice dev);

#endif
