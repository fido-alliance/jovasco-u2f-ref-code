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

#ifndef _BLEAPI_BLEAPIWINDOWS_H_
#define _BLEAPI_BLEAPIWINDOWS_H_

#include "BleApi.h"

#include <string>
#include <vector>

typedef class BleApiWindows : public BleApi {
 public:
	BleApiWindows(BleApiConfiguration &configuration);
	~BleApiWindows(void);

 public:
	 virtual std::vector < BleDevice * >findDevices();

private:
  U2FVersion mU2FVersion;
} *pBleApiWindows;

#endif				/* _BLEAPI_BLEAPIWINDOWS_H_ */
