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