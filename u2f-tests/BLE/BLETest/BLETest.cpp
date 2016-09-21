// BLETest.cpp : Defines the entry point for the console application.
//

#include <string>

#include "ble_util.h"
#include "fido_apduresponses.h"

#include "U2FTests.h"
#include "BLETransportTests.h"

#include "../BleApi/BleApi.h"
#include "../BleApi/fido_ble.h"

int arg_Verbose = 0;		// default
bool arg_hasButton = false;
bool arg_u2f = true;
bool arg_transport = true;
bool arg_iso7816 = true;

#define REPLY_BUFFER_LENGTH 256
static unsigned char reply[REPLY_BUFFER_LENGTH];
static unsigned int replyLength = REPLY_BUFFER_LENGTH;

void BleApiTestEventHandler(BleDevice::FIDOEventType type,
			    unsigned char *buffer, unsigned int bufferLength)
{
	if (type != BleDevice::EVENT_FRAGMENT)
		return;

	BleApiTest_TransportEventHandler(type, buffer, bufferLength);
}

ReturnValue GetBleInterfaceVersion(BleApiConfiguration &configuration, pBleDevice dev, bool silent = false)
{
	ReturnValue retval;

	unsigned char version[128];
	unsigned int len = sizeof(version);


	/* verify version */
  switch (configuration.version) {
  case U2FVersion::V1_0:
    /* read version */
    retval = dev->U2FVersionRead(version, &len);
    if (!retval)
      return retval;

    CHECK_EQ(memcmp(version, "1.0", 3), 0);

    if (!silent)
      INFO << "U2F BLE Version: " << std::string((char *)version, 3);

    break;

  case U2FVersion::V1_1:
    /* read version */
    retval = dev->U2FVersionBitfieldRead(version, &len);
    if (!retval)
      return retval;

    CHECK_EQ((version[FIDO_BLE_VERSIONBITFIELD_VERSION_1_1_OFFSET] & FIDO_BLE_VERSIONBITFIELD_VERSION_1_1_BIT), FIDO_BLE_VERSIONBITFIELD_VERSION_1_1_BIT);

    if (!silent)
      INFO << "U2F BLE Version: 1.1";

    break;

  default:
    return ReturnValue::BLEAPI_ERROR_NOT_IMPLEMENTED;
  }

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

static
void pause(const std::string & prompt)
{
	printf("\n%s", prompt.c_str());
	getchar();
	printf("\n");
}

void WaitForDeviceDisconnected(BleApiConfiguration &configuration, pBleDevice dev)
{
#if defined(PLATFORM_WINDOWS) && defined(FEATURE_WINRT)
  while (dev->IsConnected()) dev->Sleep(100);
#endif
}

void WaitForUserPresence(BleApiConfiguration &configuration, pBleDevice dev)
{
	ReturnValue retval;

#if defined(PLATFORM_WINDOWS) && defined(FEATURE_WINRT)
  if (dev->IsConnected() && dev->IsPaired())
    return;

  std::cout << "Turn on device." << std::endl;
  dev->WaitForDevice();

  if ((configuration.logging & BleApiLogging::Info) != 0)
    std::cout << "Connecting to device..." << std::endl;
  bool silent = false;
  do {
      /* trigger connection */
    retval = GetBleInterfaceVersion(configuration, dev, silent);
    silent = true;
    if (!retval)
      continue;
  } while (!dev->IsConnected() && dev->IsPaired());

  /* register for notification to receive data */
  if ((configuration.logging & BleApiLogging::Info) != 0)
    std::cout << "Registering notifications... " << std::endl;
  retval = dev->RegisterNotifications(BleApiTestEventHandler);
  if (retval != ReturnValue::BLEAPI_ERROR_SUCCESS)
    throw std::runtime_error(__FILE__ ":" + std::to_string(__LINE__) + ": could not register notification although we are connected.");
#else
  pause("Turn on device and hit enter..");

  /* check for U2F Interface version */
  retval = GetBleInterfaceVersion(dev);
  if (!retval)
    abort();

  /* register for notification to receive data */
  retval = dev->RegisterNotifications(BleApiTestEventHandler);
  if (!retval)
    abort();
#endif
}

ReturnValue BLETransportTests(BleApiConfiguration &configuration, pBleDevice dev)
{
	std::cout << std::endl << "==== BLE Transport tests ====" << std::endl;

	WaitForUserPresence(configuration, dev);

	// set timeout at 30 seconds, just in case devices just doesn't answer.
	dev->SetTimeout(30000);

	PASS(BleApiTest_TransportPing(dev));
	PASS(BleApiTest_TransportLongPing(dev));
	PASS(BleApiTest_TransportLimits(dev));
	PASS(BleApiTest_TransportUnknown
	     (dev, (4 + (rand() % (TYPE_INIT - 0x04)))));
	PASS(BleApiTest_TransportNotCont(dev));
	PASS(BleApiTest_TransportBadSequence(dev));
	PASS(BleApiTest_TransportContFirst(dev));
	PASS(BleApiTest_TransportTooLong(dev));

  // rest of the tests are not for 1.0
  if (configuration.version == U2FVersion::V1_0)
    return ReturnValue::BLEAPI_ERROR_SUCCESS;

  std::cout << "Waiting until device disconnects..." << std::endl;
  WaitForDeviceDisconnected(configuration, dev);

  bool pairingmode_sd_present = false, notpairingmode_sd_present = false;
  std::cout << "Turn on device NOT in Pairing Mode." << std::endl;
  PASS(BleApiTest_AdvertisingNotPairingMode(dev, notpairingmode_sd_present));
  WaitForDeviceDisconnected(configuration, dev); // just to be sure

  std::cout << "Turn on device in Pairing Mode." << std::endl;
  PASS(BleApiTest_AdvertisingPairingMode(dev, pairingmode_sd_present));
  WaitForDeviceDisconnected(configuration, dev); // just to be sure.

  // if the service data is present in 1 mode, it needs to be present in both.
  CHECK_EQ(notpairingmode_sd_present, pairingmode_sd_present)

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue U2FISO7816EncodingTests(BleApiConfiguration &configuration, pBleDevice dev)
{
	std::cout << std::endl << "==== BLE ISO7816-4 Encoding tests ====" <<
	    std::endl;
	WaitForUserPresence(configuration, dev);

	PASS(BleApiTest_TestEncodingLongAnyLength(dev));
	PASS(BleApiTest_TestEncodingLongExactLength(dev));
	PASS(BleApiTest_TestEncodingLongWrongLength(dev));

	// must do enroll before long data tests because it uses
	//   Sign command.
	BleApiTest_Enroll(dev);

  WaitForDeviceDisconnected(configuration, dev);
	WaitForUserPresence(configuration, dev);
	PASS(BleApiTest_TestEncodingLongDataAnyLength(dev));

  WaitForDeviceDisconnected(configuration, dev);
  WaitForUserPresence(configuration, dev);
	PASS(BleApiTest_TestEncodingLongDataExactLength(dev));

  WaitForDeviceDisconnected(configuration, dev);
  WaitForUserPresence(configuration, dev);
	PASS(BleApiTest_TestEncodingLongDataWrongLength(dev));

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

ReturnValue U2FTests(BleApiConfiguration &configuration, pBleDevice dev)
{
	std::cout << std::endl << "==== U2F Raw Message tests ====" << std::
	    endl;
	WaitForUserPresence(configuration, dev);

	PASS(BleApiTest_GetU2FProtocolVersion(dev));
	PASS(BleApiTest_UnknownINS(dev));
	PASS(BleApiTest_BadCLA(dev));
	PASS(BleApiTest_VersionWrongLength(dev));
	PASS(BleApiTest_RegisterWrongLength(dev));

	PASS(BleApiTest_Enroll(dev));

  WaitForDeviceDisconnected(configuration, dev);
  WaitForUserPresence(configuration, dev);

	// Sign with wrong kh.
	PASS(BleApiTest_Sign(dev, NULL, FIDO_RESP_WRONG_DATA, false, true, false));

	// Sign with wrong AppID.
	PASS(BleApiTest_Sign(dev, NULL, FIDO_RESP_WRONG_DATA, false, false, true));

	// Sign with check only should not produce signature.
	PASS(BleApiTest_Sign(dev, NULL, FIDO_RESP_USERPRESENCE_REQUIRED, true));

	uint32_t ctr1;
	PASS(BleApiTest_Sign(dev, &ctr1));

  WaitForDeviceDisconnected(configuration, dev);
  WaitForUserPresence(configuration, dev);

	uint32_t ctr2;
	PASS(BleApiTest_Sign(dev, &ctr2));

	// Ctr should have incremented by 1.
	PASS(ctr2 == (ctr1 + 1));

  // to be sure.
  WaitForDeviceDisconnected(configuration, dev);

	return ReturnValue::BLEAPI_ERROR_SUCCESS;
}

void Usage(char *name)
{
	std::cerr << "Usage: " << name << std::endl
	    <<
	    " [ -d <device-identifier>] [-l] [-h] [-a] [-v] [-V] [-p] [-e] [-u] [-t] [-w] [-i]"
	    << std::endl
	    << "  -h   : this text." << std::endl
	    << "  -a   : Do not abort on failed test." << std::endl
	    << "  -v   : Verbose" << std::endl
	    << "  -V   : Even more verbose" << std::endl
	    << "  -p   : Pause at failed test" << std::endl
	    << "  -u   : Disable U2F Raw Message tests. " << std::endl
	    << "  -t   : Disable BLE Transport tests." << std::endl
	    << "  -i   : Disable U2F ISO7816-4 encoding tests." << std::endl
	    << "  -w   : Warnings are treated as errors." << std::endl
	    << "  -x   : Disable encrypted connection requirement." << std::endl
	    << "  -c   : Toggle ANSI colors." << std::endl
	    << "  -l   : Show all known FIDO BLE devices and exit." << std::endl
	    << "  -d   : Select specific FIDO BLE device." << std::endl
	    << "  -T   : turn on BLE level tracing." << std::endl
      << "  -1.0 : Select U2F Version 1.0" << std::endl
      << "  -1.1 : Select U2F Version 1.1 (default)" << std::endl
    ;
	exit(-1);
}

int __cdecl main(int argc, char *argv[])
{
	int count = 1;
	pBleDevice dev = NULL;
	bool arg_ShowDevices = false;
	char *arg_DeviceIdentifier = NULL;
  BleApiConfiguration  configuration;

	while (count < argc) {
		if (!strncmp(argv[count], "-v", 2)) {
			// INFO only
      configuration.logging |= BleApiLogging::Info;
      arg_Verbose |= 1;
		}
		if (!strncmp(argv[count], "-V", 2)) {
			// INFO only
      configuration.logging |= BleApiLogging::Debug;
      arg_Verbose |= 2;
    }
		if (!strncmp(argv[count], "-a", 2)) {
			// Don't abort, try continue;
			arg_Abort = false;
		}
		if (!strncmp(argv[count], "-p", 2)) {
			// Pause at abort
			arg_Pause = true;
		}
		if (!strncmp(argv[count], "-h", 2)) {
			Usage(argv[0]);
		}
		if (!strncmp(argv[count], "-b", 2)) {
			// Fob does not have button
			arg_hasButton = false;
		}
    if (!strncmp(argv[count], "-e", 2)) {
      // fob uses pre-approval
      std::cout << "WARNING: -e option default and removed." << std::endl;
    }
		if (!strncmp(argv[count], "-u", 2)) {
			// skip u2f tests
			arg_u2f = false;
		}
		if (!strncmp(argv[count], "-t", 2)) {
			// skip ble tests
			arg_transport = false;
		}
		if (!strncmp(argv[count], "-i", 2)) {
			// skip iso7816 tests
			arg_iso7816 = false;
		}
		if (!strncmp(argv[count], "-w", 2)) {
			// treat warnings as errors
			arg_LethalWarn = false;
		}
		if (!strncmp(argv[count], "-l", 2)) {
			// treat warnings as errors
			arg_ShowDevices = true;
		}
		if (!strncmp(argv[count], "-T", 2)) {
			// treat warnings as errors
      configuration.logging |= BleApiLogging::Tracing;
		}
    if (!strncmp(argv[count], "-1.0", 4)) {
      configuration.version = U2FVersion::V1_0;
    }
    if (!strncmp(argv[count], "-1.1", 4)) {
      configuration.version = U2FVersion::V1_1;
    }
    if (!strncmp(argv[count], "-d", 2)) {
			// treat warnings as errors
			++count;
			if (count == argc) {
				std::cerr << "Argument required for -d." <<
				    std::endl;
				Usage(argv[0]);
			}
			arg_DeviceIdentifier = argv[count];
		}
		if (!strncmp(argv[count], "-x", 2)) {
			configuration.encrypt = false;
			std::cout << "BLE connection encryption disabled." <<
			    std::endl;
		}
		if (!strncmp(argv[count], "-c", 2)) {
			arg_ansi = !arg_ansi;
		}
		++count;
	}

  std::cout << "BLE Certification Tool " << VERSION << std::endl;

	try {
		pBleApi api = BleApi::CreateAPI(configuration);

		/* find U2F Devices */
		std::vector < pBleDevice > devices = api->findDevices();

		/* no devices found */
		if (!devices.size())
			return -1;

		/* show all valid devices? */
		if (arg_ShowDevices) {
			std::vector < pBleDevice >::iterator i;

			std::cout << "All valid FIDO BLE devices:" << std::endl;
			for (i = devices.begin(); i != devices.end(); i++) {
				std::cout << "  " << (*i)->Identifier() << std::
				    endl;
			}
			exit(0);
		}

		/* select a specific device ? */
		if (arg_DeviceIdentifier) {
			std::string id(arg_DeviceIdentifier);
			std::vector < pBleDevice >::iterator i;

			for (i = devices.begin(); i != devices.end(); i++) {
				if (((*i)->Identifier() == id)
				    && ((*i)->Identifier().length() ==
					id.length()))
					dev = (*i);
			}
		} else {
			/* grab the first device */
			dev = devices[0];
		}

		/* verify device is valid. */
		if (!dev) {
			std::cout << "No valid device found.\n" << std::endl;
			exit(-1);
		}
    std::cout << std::endl;

    /* report device details and verify device is according to spec */
    std::cout << "==== Selected Device ====" << std::endl;
    dev->Report();
    dev->Verify();
    std::cout << std::endl;

    /* report on configuration selection */
    std::cout << "==== Configuration ====" << std::endl;
    std::cout << "U2F Version: ";
    switch (configuration.version)
    {
    case U2FVersion::V1_0:
      std::cout << "1.0";
      break;
    case U2FVersion::V1_1:
      std::cout << "1.1";
      break;
    default:
      break;
    }
    std::cout << std::endl;
    std::cout << "Encryption : " << (configuration.encrypt ? "Yes" : "No") << std::endl;
    std::cout << "Adaptive   : " << (configuration.adaptive? "Yes" : "No") << std::endl;
    std::cout << "Logging    : " << (configuration.logging & BleApiLogging::Info ? "Info " : "") << (configuration.logging & BleApiLogging::Debug ? "Debug " : "") << (configuration.logging & BleApiLogging::Tracing ? "Tracing" : "") << std::endl;
    std::cout << std::endl;

    /* something to do? */
    if (!(arg_transport || arg_u2f || arg_iso7816)) {
      std::cout << "Nothing to do." << std::endl;
      return 0;
    }

    std::cout << "==== Selected Tests ====" << std::endl;
    std::cout << "BLE Transport Tests    : " << (arg_transport ? "Yes" : "No") << std::endl;
    std::cout << "U2F Raw Messages Tests : " << (arg_u2f       ? "Yes" : "No") << std::endl;
    std::cout << "ISO7816-4 Tests        : " << (arg_iso7816   ? "Yes" : "No") << std::endl;
    std::cout << std::endl;

		/* check that link encryption is enabled */
		WARN_EQ(configuration.encrypt, true);


    std::cout << "=== Starting Tests === " << std::endl;

		/* do ble transport tests */
		if (arg_transport) {
			if (!BLETransportTests(configuration, dev))
				return -1;
		}

		/* do the u2f tests */
		if (arg_u2f) {
			if (!U2FTests(configuration, dev))
				return -1;
		}

		/* do the iso7816-4 tests */
		if (arg_iso7816) {
			if (!U2FISO7816EncodingTests(configuration, dev))
				return -1;

		}
	}
	catch(std::exception e) {
		std::cout << "ERROR: " << e.what() << std::endl;

		return -1;
	}

	std::cout << std::endl << "==== Test completed. ====" << std::endl;

	return 0;
}
