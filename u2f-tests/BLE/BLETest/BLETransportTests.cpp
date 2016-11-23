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

#include "BLETransportTests.h"

#include "fido_ble.h"
#include "ble_util.h"

bool eventDone = true;

#define REPLY_BUFFER_LENGTH  	512
unsigned char fragmentReplyBuffer[REPLY_BUFFER_LENGTH];
unsigned int fragmentReplyBufferLength;

bool ScanForUuid(std::vector<unsigned char> field, unsigned short uuid)
{
  bool retval = false;
  unsigned char msb = ((uuid >> 8) & 0xFF), lsb = (uuid & 0xFF);

  for (unsigned int i = 0; (!retval) && (i < field.size()); i += 2)
    if ((field[i] == lsb) && (field[i + 1] == msb))
      retval = true;

  return retval;
}

ReturnValue WaitForEvent(pBleDevice dev, unsigned int timeout)
{
	uint64_t deadline = dev->TimeMs() + timeout;

	while (!eventDone && ((timeout == 0) || (deadline > dev->TimeMs()))) {
		dev->Sleep(100);
	}

	if (!eventDone)
		return ReturnValue::BLEAPI_ERROR_TIMEOUT;

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

void BleApiTest_TransportEventHandler(BleDevice::FIDOEventType type,
				      unsigned char *buffer,
				      unsigned int bufferLength)
{
	// are we waiting for input?
	if (eventDone)
		return;

	// ignore keep-alives here.     
	if (buffer[0] == FIDO_BLE_CMD_KEEPALIVE)
		return;

	memcpy(fragmentReplyBuffer, buffer, bufferLength);
	fragmentReplyBufferLength = bufferLength;

	eventDone = true;
}

ReturnValue BleApiTest_TransportPing(BleApiConfiguration &config, pBleDevice dev)
{
	ReturnValue retval;
	float sent, received;

	unsigned int i;
	unsigned char request[8];
	unsigned int requestLength = 8;
	unsigned char reply[8];
	unsigned int replyLength = 8;
	unsigned char replyCmd = 0;

	for (i = 0; i < requestLength; i++)
		request[i] = (rand() & 0xFF);

	sent = (float)dev->TimeMs();
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_PING, request, requestLength,
			      &replyCmd, reply, &replyLength);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	received = (float)dev->TimeMs();
	INFO << "Sent " << requestLength << " bytes in " << (received -
							     sent) /
	    1000.0 << " s.";

	CHECK_EQ(replyCmd, FIDO_BLE_CMD_PING, "Expected FIDO_BLE_CMD_PING (0x81) reply.");
	CHECK_EQ(replyLength, requestLength, "Reply length should equal request length.");
	CHECK_EQ(memcmp(request, reply, requestLength), 0, "Reply should be equal to request.");

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TransportUnknown(BleApiConfiguration &config, pBleDevice dev, unsigned char cmd)
{
	ReturnValue retval;
	float sent, received;

	unsigned int i;
	unsigned char request[8];
	unsigned int requestLength = 0;
	unsigned char reply[8];
	unsigned int replyLength = 8;
	unsigned char replyCmd = 0;

	// always set INIT bit
	cmd |= 0x80;

	for (i = 0; i < sizeof(request); i++)
		request[i] = (rand() & 0xFF);

	sent = (float)dev->TimeMs();
	retval =
	    dev->CommandWrite(cmd, request, requestLength, &replyCmd, reply,
			      &replyLength);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	received = (float)dev->TimeMs();
	INFO << "Sent cmd 0x" << std::hex << (int)cmd << std::dec << " with " <<
	    requestLength << " bytes in " << (received - sent) / 1000.0 << "s.";

	CHECK_EQ(replyCmd, FIDO_BLE_CMD_ERROR, "Reply should be FIDO_BLE_CMD_ERROR (0xBF).");
	WARN_EQ(replyLength, 1/* , "Reply should be 1 byte long." */);
	WARN_EQ(reply[0], ERR_INVALID_CMD/* , "Reply should contain ERR_INVALID_CMD (0x01)" */);

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TransportLongPing(BleApiConfiguration &config, pBleDevice dev)
{
	ReturnValue retval;
	float sent, received;

	unsigned int i;
	unsigned char request[128];
	unsigned int requestLength = 128;
	unsigned char reply[128];
	unsigned int replyLength = 128;
	unsigned char replyCmd = 0;

	for (i = 0; i < requestLength; i++)
		request[i] = (rand() & 0xFF);

	sent = (float)dev->TimeMs();
	retval =
	    dev->CommandWrite(FIDO_BLE_CMD_PING, request, requestLength,
			      &replyCmd, reply, &replyLength);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	received = (float)dev->TimeMs();
	INFO << "Sent " << requestLength << " bytes in " << (received -
							     sent) /
	    1000.0 << "s.";

  CHECK((replyCmd == FIDO_BLE_CMD_PING)||(replyCmd == FIDO_BLE_CMD_ERROR), "Ping should return PING or ERROR.");
  if (replyCmd == FIDO_BLE_CMD_PING) {
    CHECK_EQ(replyLength, requestLength, "Ping reply has to be same length as request.");
    CHECK_EQ(memcmp(request, reply, requestLength), 0, "Ping reply must be equal to ping request.");
  } else {
    CHECK_EQ(replyLength, 1,"Error Reply should contain 1 data byte.");
    WARN_EQ(reply[0], ERR_INVALID_LEN /*, "Reply should be ERR_INVALID_LEN (0x03)" */);
  }
	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

#define LIMITS_MAXLENGTH		((1 << 16))
ReturnValue BleApiTest_TransportLimits(BleApiConfiguration &config, pBleDevice dev)
{
	ReturnValue retval;
	float sent, received;

	unsigned int i, l;
	unsigned char request[LIMITS_MAXLENGTH];
	unsigned int requestLength;
	unsigned char reply[LIMITS_MAXLENGTH];
	unsigned int replyLength;
	unsigned char replyCmd = 0;

	for (i = 0; i < LIMITS_MAXLENGTH; i++)
		request[i] = (rand() & 0xFF);

	l = 256;
	do {
		INFO << "Testing with " << l << " bytes.";
		requestLength = l;
		replyLength = l;

		sent = (float)dev->TimeMs();
		retval =
		    dev->CommandWrite(FIDO_BLE_CMD_PING, request, requestLength,
				      &replyCmd, reply, &replyLength);
		CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS,"CommandWrite failed.");

		received = (float)dev->TimeMs();

    CHECK((replyCmd == FIDO_BLE_CMD_PING) || (replyCmd == FIDO_BLE_CMD_ERROR), "PING CMD should return PING or ERROR.");
    if (replyCmd == FIDO_BLE_CMD_PING) {
			CHECK_EQ(replyLength, l, "Ping reply has to be same length as request.");
			CHECK_EQ(memcmp(request, reply, l), 0, "Ping reply must be equal to ping request.");
			INFO << "  Sent " << requestLength << " bytes in " <<
			    (received - sent) / 1000.0 << "s.";
		} else if (replyCmd == FIDO_BLE_CMD_ERROR) {
			CHECK_EQ(replyLength, 1, "Error Reply should contain 1 data byte.");
			WARN_EQ(reply[0], ERR_INVALID_LEN /*, "Reply should be ERR_INVALID_LEN (0x03)" */);
			INFO << "  Limit is smaller than " << requestLength <<
			    " bytes.";
		}

		l <<= 1;
	}
	while (replyCmd == FIDO_BLE_CMD_PING);

  INFO << "Waiting to make sure all error replies are received before we continue.";
	dev->Sleep(1500);

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TransportNotCont(BleApiConfiguration &config, pBleDevice dev)
{
	ReturnValue retval;

	unsigned int cpl, l;
	unsigned char request[8192] = { FIDO_BLE_CMD_MSG, 0x00, 0x20, };

	// get control point length
	retval = dev->ControlPointLengthRead(&cpl);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	eventDone = false;

  // BT v4.2 Vol3, Part F, 3.2.9
	CHECK_LE(cpl, 512, "ControlPointLength can't be larger than 512.");

	// write needs to be longer than cpl
	l = cpl + 1;
	request[1] = (l >> 8) & 0xFF;
	request[2] = (l) & 0xFF;

	// send first INIT frame
	retval = dev->ControlPointWrite(request, cpl);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	// no reply expected

	// send INIT frame again while CONT is expected
	retval = dev->ControlPointWrite(request, cpl);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	retval = WaitForEvent(dev, 10000);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	// check if this is error reply
	CHECK_EQ(fragmentReplyBuffer[0], FIDO_BLE_CMD_ERROR, "Expected FIDO_BLE_CMD_ERROR (0xBF)");

	// check total reply length
	WARN_EQ(fragmentReplyBufferLength, 3 /* header */  + 1 /* data *//* , "Expected fragmentation header and 1 data byte." */);
	// check 1 data byte length
	WARN_EQ((((short)fragmentReplyBuffer[1]) << 8 | fragmentReplyBuffer[2]), 1 /*, "Expected 1 data byte." */);
	// check invalid seq error
	WARN_EQ(fragmentReplyBuffer[3], ERR_INVALID_SEQ/* , "Expected ERR_INVALID_SEQ (0x04)" */);

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TransportBadSequence(BleApiConfiguration &config, pBleDevice dev)
{
	ReturnValue retval;

	unsigned int cpl;
	unsigned char request[8192 * 2] = { FIDO_BLE_CMD_MSG, };

	// get control point length
	retval = dev->ControlPointLengthRead(&cpl);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	eventDone = false;

	CHECK_LE(cpl, 8192);

	// build correct request
	request[0] = FIDO_BLE_CMD_MSG;
	request[1] = (cpl >> 8) & 0xFF;
	request[2] = cpl & 0xFF;

	// wrong sequence, should be 0 
	request[cpl] = 0x01;

	// send first INIT frame
	retval = dev->ControlPointWrite(request, cpl);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	// no reply expected

	// send CONT frame with bad sequence number
	retval = dev->ControlPointWrite(request + cpl, cpl);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	// wait upto 10 seconds for a reply.
	retval = WaitForEvent(dev, 10000);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	// check if this is error reply
  CHECK_EQ(fragmentReplyBuffer[0], FIDO_BLE_CMD_ERROR, "Expected FIDO_BLE_CMD_ERROR (0xBF)");

	// should have length of 3 header + 1 data byte
  WARN_EQ(fragmentReplyBufferLength, 3 /* header */ + 1 /* data *//* , "Expected fragmentation header and 1 data byte." */);

	// check 1 data byte length
  WARN_EQ((((short)fragmentReplyBuffer[1]) << 8 | fragmentReplyBuffer[2]), 1 /*, "Expected 1 data byte."*/);

	// check invalid seq error
  WARN_EQ(fragmentReplyBuffer[3], ERR_INVALID_SEQ/* , "Expected ERR_INVALID_SEQ (0x04)" */);

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TransportContFirst(BleApiConfiguration &config, pBleDevice dev)
{
	ReturnValue retval;

	unsigned int cpl;
	unsigned char request[1024] = { FIDO_BLE_CMD_MSG, };

	// get control point length
	retval = dev->ControlPointLengthRead(&cpl);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	eventDone = false;

	// build correct request
	request[0] = 0;

	// send CONT frame
	retval = dev->ControlPointWrite(request, cpl);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	// wait upto 10 seconds for a reply.
	retval = WaitForEvent(dev, 10000);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	// check if this is error reply
  CHECK_EQ(fragmentReplyBuffer[0], FIDO_BLE_CMD_ERROR, "Expected FIDO_BLE_CMD_ERROR (0xBF)");

	// should have length of 3 header + 1 data byte
	WARN_EQ(fragmentReplyBufferLength, 3 /* header */  + 1 /* data *//* , "Expected fragmentation header and 1 data byte." */);
	// check 1 data byte length
	WARN_EQ((((short)fragmentReplyBuffer[1]) << 8 | fragmentReplyBuffer[2]),
		1 /*, "Expected 1 data byte."*/);

	// check invalid seq error
	WARN_EQ(fragmentReplyBuffer[3], ERR_INVALID_SEQ/* , "Expected ERR_INVALID_SEQ (0x04)" */);

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_TransportTooLong(BleApiConfiguration &config, pBleDevice dev)
{
	ReturnValue retval;

	unsigned int cpl;
	unsigned char request[1024] = { FIDO_BLE_CMD_PING, 0x00, 0x01, };

	// get control point length
	retval = dev->ControlPointLengthRead(&cpl);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	eventDone = false;

	// send INIT frame with too much data
	retval = dev->ControlPointWrite(request, cpl);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	// wait upto 10 seconds for a reply.
	retval = WaitForEvent(dev, 10000);
	CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS);

	// check if this is error reply
	CHECK_EQ(fragmentReplyBuffer[0], FIDO_BLE_CMD_ERROR, "Expected FIDO_BLE_CMD_ERROR (0xBF)");

	// should have length of 3 header + 1 data byte
	WARN_EQ(fragmentReplyBufferLength, 3 /* header */  + 1 /* data *//* , "Expected fragmentation header and 1 data byte." */);
	// check 1 data byte length
	WARN_EQ((((short)fragmentReplyBuffer[1]) << 8 | fragmentReplyBuffer[2]),
		1 /*, "Expected 1 data byte." */);
	// check invalid seq error
	WARN_EQ(fragmentReplyBuffer[3], ERR_INVALID_LEN/* , "Expected ERR_INVALID_SEQ (0x04)" */);

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_AdvertisingNotPairingMode(BleApiConfiguration &config, pBleDevice dev, bool &servicedata_present)
{
  // if we don't support V1.1, this test is not applicable.
  if (!dev->SupportsVersion(U2FVersion::V1_1))
    return ReturnValue::BLEAPI_ERROR_SUCCESS;

  // unpairing before connecting
  ReturnValue retval = dev->Unpair();
  if (!retval)
    return retval;

  // collect advertisement and scan response.
  BleAdvertisement *adv = NULL, *scanresp = NULL;
  retval = dev->WaitForDevice(&adv, &scanresp);
  if (!retval)
    return retval;

  // check FIDO UUID in all possible fields in both adv and scan response packets.
  auto shortuuids = adv->GetSection(BleAdvertisementSectionType::More16bitUuid);
  if (!ScanForUuid(shortuuids, FIDO_SERVICE_SHORTUUID)) {
    shortuuids = adv->GetSection(BleAdvertisementSectionType::Complete16bitUuid);
    if (!ScanForUuid(shortuuids, FIDO_SERVICE_SHORTUUID)) {
      shortuuids = scanresp->GetSection(BleAdvertisementSectionType::More16bitUuid);
      if (!ScanForUuid(shortuuids, FIDO_SERVICE_SHORTUUID)) {
        shortuuids = scanresp->GetSection(BleAdvertisementSectionType::Complete16bitUuid);
      }
    }
  }

  // FIDO UUID must be advertised.
  CHECK_EQ(ScanForUuid(shortuuids, FIDO_SERVICE_SHORTUUID), true, "Missing FIDO UUID in advertisement.");

  // check flags
  const auto flags = adv->GetSection(BleAdvertisementSectionType::Flags);

  // check if fields is present.
  CHECK_EQ(flags.empty(), false, "Flags field is mandatory.");
    
  // in non-pairing mode this needs to be zero
  CHECK_EQ(flags[0] & (BleFlagFields::LEGeneralDiscoverabilityMode | BleFlagFields::LELimitedDiscoverabilityMode), 0, "In not pairing mode, LE General and LE Limited Discoverability bits must be 0.");

  servicedata_present = false;
  // check optional service data field
  const auto servicedata = scanresp->GetSection(BleAdvertisementSectionType::ServiceData);
  if (!servicedata.empty()) {
    // check if it is fido service data
    if (!((servicedata[0] == 0xFD) && (servicedata[1] == 0xFF)))
      return ReturnValue::BLEAPI_ERROR_SUCCESS;

    INFO << "Service Data field present." << std::endl;
    servicedata_present = true;

    unsigned char serviceflags = servicedata[2];
    // not pairing mode, flag must be off.
    CHECK_EQ(serviceflags & FIDO_BLE_SERVICEDATA_PAIRINGMODE, 0);
  }

  INFO << "Device found. Trying to pair...";

  // we are NOT in pairing mode, so this should fail...
  retval = dev->Pair();
  CHECK_NE(retval, ReturnValue::BLEAPI_ERROR_SUCCESS, "Pairing must fail when not in pairing mode.");
  if (!(!retval)) 
    return ReturnValue::BLEAPI_ERROR_UNKNOWN_ERROR;

  Sleep(250);

  // we wait for the device to turn itself off again.
  if (!config.continuous) {
    INFO << "Waiting until the device stops advertising." << std::endl;
    dev->WaitForAdvertisementStop();
  }

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_AdvertisingPairingMode(BleApiConfiguration &config, pBleDevice dev, bool &servicedata_present)
{
  // if we don't support V1.1, this test is not applicable.
  if (!dev->SupportsVersion(U2FVersion::V1_1))
    return ReturnValue::BLEAPI_ERROR_SUCCESS;

  ReturnValue retval;
  // in continuous mode, the device always advertises and we ahve to wait until the advertising changes
  //   before we continue.
  if (config.continuous) {
    retval = dev->WaitForAdvertisement(true);
    if (!retval)
      return retval;
  }

  retval = dev->Unpair();
  if (!retval)
    return retval;

  Sleep(250);

  // collect advertisement and scan response.
  BleAdvertisement *adv, *scanresp;
  retval = dev->WaitForDevice(&adv, &scanresp);
  if (!retval)
    return retval;

  // check flags
  const auto flags = adv->GetSection(BleAdvertisementSectionType::Flags);
  //   check if fields is present.
  CHECK_EQ(flags.empty(), false, "The Flags field is mandatory.");
  //   in pairing mode this needs to be non-zero
  CHECK_NE((flags[0] & (BleFlagFields::LEGeneralDiscoverabilityMode | BleFlagFields::LELimitedDiscoverabilityMode)), 0, "In Pairing mode, either the LE General Discoverability or the LE Limited Discoverability mode needs to be on.");

  // check optional service data field in scan response
  servicedata_present = false;
  const auto servicedata = scanresp->GetSection(BleAdvertisementSectionType::ServiceData);
  if (!servicedata.empty()) {
    // check if it is fido service data
    if (!((servicedata[0] == 0xFD) && (servicedata[1] == 0xFF)))
      return ReturnValue::BLEAPI_ERROR_SUCCESS;

    INFO << "Service Data field present." << std::endl;
    servicedata_present = true;

    unsigned char serviceflags = servicedata[2];
    // pairing mode, flag must be on
    CHECK_EQ(serviceflags & FIDO_BLE_SERVICEDATA_PAIRINGMODE, FIDO_BLE_SERVICEDATA_PAIRINGMODE, "Service Data Field is present but pairing mode bit is not set in Pairing mode.");

    // pairing mode, authenticated. Should require a PIN (or OOB).
    if (dev->IsAuthenticated())
      CHECK_EQ(serviceflags & FIDO_BLE_SERVICEDATA_PASSKEYENTRY, FIDO_BLE_SERVICEDATA_PASSKEYENTRY, "The link is authenticated but the device does not indicate that it requires a Passkey Entry.");
  }

  INFO << "Device found. Trying to pair...";

  // we are in pairing mode, so this should succeed...
  retval = dev->Pair();
  CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS, "Pairing failed.");
  if (!retval)
    return retval;

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_VersionSelection(BleApiConfiguration &config, pBleDevice dev, bool &servicedata_present)
{
  // if we don't support V1.1, this test is not applicable.
  if (!dev->SupportsVersion(U2FVersion::V1_1))
    return ReturnValue::BLEAPI_ERROR_SUCCESS;

  ReturnValue retval;
  unsigned char buffer[512];
  unsigned int  length = sizeof(buffer);
  retval = dev->U2FVersionBitfieldRead(buffer, &length);
  if (!retval)
    return retval;

  switch (config.version)
  {
  case U2FVersion::V1_1:
    CHECK_GE(length, 1, "u2fVersionBitfield must be 1 byte or longer.");
    break;
  default:
    CHECK(false, "Version not supported in this test.");
    return ReturnValue::BLEAPI_ERROR_NOT_IMPLEMENTED;
  }

  // writing buffer
  unsigned char writebuffer[512];
  unsigned int  writelength = length;
  memset(writebuffer, 0, sizeof(writebuffer));

  // find a version bit. Only supports 8 first versions for now.
  unsigned char b = 0x80;
  while (!(buffer[0] & b) && b)
    b >>= 1;
  if (!b)
    return ReturnValue::BLEAPI_ERROR_NOT_FOUND;

  // write bit to versio characteristic. should work.
  retval = dev->U2FVersionBitfieldWrite(writebuffer, &writelength);
  CHECK_EQ(retval, ReturnValue::BLEAPI_ERROR_SUCCESS, "Selecting the version failed.");

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue BleApiTest_VersionSelectionWrong(BleApiConfiguration &config, pBleDevice dev, bool &servicedata_present)
{
  // if we don't support V1.1, this test is not applicable.
  if (!dev->SupportsVersion(U2FVersion::V1_1))
    return ReturnValue::BLEAPI_ERROR_SUCCESS;

  ReturnValue retval;
  unsigned char buffer[512];
  unsigned int  length = sizeof(buffer);
  retval = dev->U2FVersionBitfieldRead(buffer, &length);
  if (!retval)
    return retval;

  switch (config.version)
  {
  case U2FVersion::V1_1:
    CHECK_GE(length, 1, "u2fVersionBitfield must be 1 byte or longer.");
    break;
  default:
    CHECK(false, "Version not supported in this test.");
    return ReturnValue::BLEAPI_ERROR_NOT_IMPLEMENTED;
  }

  // writing buffer
  unsigned char writebuffer[512];
  unsigned int  writelength = length;
  memset(writebuffer, 0, sizeof(writebuffer));

  // find a version bit that isn't set. works only for first 8 bits.
  unsigned char b = 0x80;
  while ((buffer[0] & b) && b)
    b >>= 1;
  if (!b)
    return ReturnValue::BLEAPI_ERROR_NOT_FOUND;

  // write bit to version characteristic. should NOT work.
  retval = dev->U2FVersionBitfieldWrite(writebuffer, &writelength);
  CHECK_NE(retval, ReturnValue::BLEAPI_ERROR_SUCCESS, "Selecting the version failed.");

  return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

