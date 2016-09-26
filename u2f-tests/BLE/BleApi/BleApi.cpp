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

#include "BleApi.h"

#ifdef PLATFORM_WINDOWS
#ifdef FEATURE_WINRT
#include "BleApiWinRT.h"
#else
#include "BleApiWindows.h"
#endif
#else
#error "Please define a platform."
#endif

#include <guiddef.h>

 BleApi::BleApi(BleApiConfiguration &configuration):
mConfiguration(configuration)
{
}

BleApi::~BleApi(void)
{
	while (mDeviceList.size()) {
		BleDevice *dev = mDeviceList.back();
		mDeviceList.pop_back();

		delete dev;
	}
}

// Overridden in platform specific version.
std::vector < BleDevice * >BleApi::findDevices()
{
	std::vector < BleDevice * >empty;
	return empty;
}

bool BleApi::IsEnabled()
{
  return false;
}

BleApi *BleApi::CreateAPI(BleApiConfiguration &configuration)
{
#ifdef PLATFORM_WINDOWS
#ifdef FEATURE_WINRT
  return (pBleApi) new BleApiWinRT(configuration);
#else
	return (pBleApi) new BleApiWindows(version, encryption, logging);
#endif
#else
	return NULL;
#endif
}
