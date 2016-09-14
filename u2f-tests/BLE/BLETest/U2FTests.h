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

#include "../BleApi/BleApi.h"

extern ReturnValue BleApiTest_GetU2FProtocolVersion(pBleDevice dev);
extern ReturnValue BleApiTest_UnknownINS(pBleDevice dev);
extern ReturnValue BleApiTest_BadCLA(pBleDevice dev);
extern ReturnValue BleApiTest_VersionWrongLength(pBleDevice dev);
extern ReturnValue BleApiTest_RegisterWrongLength(pBleDevice dev);
extern ReturnValue BleApiTest_Enroll(pBleDevice dev, int expectedSW12 = 0x9000);
extern uint32_t BleApiTest_Sign(pBleDevice dev, int expectedSW12 =
				0x9000, bool checkOnly = false, bool corruptKH =
				false, bool corruptAddId = false);

extern ReturnValue BleApiTest_TestEncodingShortAnyLength(pBleDevice dev);
extern ReturnValue BleApiTest_TestEncodingShortExactLength(pBleDevice dev);
extern ReturnValue BleApiTest_TestEncodingShortWrongLength(pBleDevice dev);
extern ReturnValue BleApiTest_TestEncodingLongAnyLength(pBleDevice dev);
extern ReturnValue BleApiTest_TestEncodingLongExactLength(pBleDevice dev);
extern ReturnValue BleApiTest_TestEncodingLongWrongLength(pBleDevice dev);
extern ReturnValue BleApiTest_TestEncodingLongDataAnyLength(pBleDevice dev);
extern ReturnValue BleApiTest_TestEncodingLongDataExactLength(pBleDevice dev);
extern ReturnValue BleApiTest_TestEncodingLongDataWrongLength(pBleDevice dev);
