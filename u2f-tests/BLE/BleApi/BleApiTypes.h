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

#ifndef _BLEAPI_BLEAPITYPES_H_
#define _BLEAPI_BLEAPITYPES_H_

typedef enum {
  V1_0,
  V1_1,
} U2FVersion;

typedef enum {
  Default = 0,
  Info    = 1,
  Debug   = 2,
  Tracing = 4,
} BleApiLogging;

typedef enum {
  Advertisement = 0,
  ScanResponse = 1,
} BleAdvertisementType;

typedef enum {
  Flags               = 0x01,
  More16bitUuid       = 0x02,
  Complete16bitUuid   = 0x03,
  More32bitUuid       = 0x04,
  Compelte32bitUuid   = 0x05,
  More128bitUuid      = 0x06,
  Compelte128bitUuid  = 0x07,
  LocalName           = 0x08,
  LocalNameComplete   = 0x09,
  TxPowerLevel        = 0x0A,
  ServiceData         = 0x16,
} BleAdvertisementSectionType;

typedef enum {
  LELimitedDiscoverabilityMode = 0x01,
  LEGeneralDiscoverabilityMode = 0x02,
} BleFlagFields;

typedef class BleApiConfiguration {
public:
  // set defaults.
  BleApiConfiguration() : version (V1_1), logging(Default), encrypt(true), adaptive(false) {};

  U2FVersion      version;  // U2F version used by the API
  unsigned int    logging;  // enable detailed logging
  bool            encrypt;  // enable link encryption
  bool            adaptive; // enable adaptive write formats (WriteWithoutResponse, ...)
                            //   depending on what the device supports
                            //   if this is disabled, always uses WriteWithResponse
} BleApiConfiguration;

#endif /* _BLEAPI_BLEAPITYPES_H_ */