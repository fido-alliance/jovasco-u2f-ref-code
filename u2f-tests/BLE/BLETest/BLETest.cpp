// BLETest.cpp : Defines the entry point for the console application.
//

#include "ble_util.h"
#include "fido_apduresponses.h"

#include "U2FTests.h"
#include "BLETransportTests.h"

#include "../BleApi/BleApi.h"
#include "../BleApi/fido_ble.h"

int arg_Verbose = 0;		// default
bool arg_hasButton = false;
bool arg_preapproval = false;
bool arg_u2f = true;
bool arg_transport = true;
bool arg_iso7816 = false;
bool arg_encryption = true;

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

ReturnValue GetBleInterfaceVersion(pBleDevice dev)
{
	ReturnValue retval;

	unsigned char version[128];
	unsigned int len = sizeof(version);

	/* read version */
	retval = dev->U2FVersionRead(version, &len);
	if (retval != BLEAPI_ERROR_SUCCESS)
		return retval;

	/* verify version */
	CHECK_EQ(memcmp(version, "1.0", 3), 0);

	INFO << "U2F BLE Version: " << version;

	return BLEAPI_ERROR_SUCCESS;
}

static
void pause(const std::string & prompt)
{
	printf("\n%s", prompt.c_str());
	getchar();
	printf("\n");
}

void WaitForUserPresence(pBleDevice dev, bool hasButton)
{
	ReturnValue retval;

	pause(std::string(hasButton ? "Touch" : "Turn on") +
	      " device and hit enter..");

	/* check for U2F Interface version */
	retval = GetBleInterfaceVersion(dev);
	if (retval != BLEAPI_ERROR_SUCCESS)
		abort();

	/* register for notification to receive data */
	retval = dev->RegisterNotifications(BleApiTestEventHandler);
	if (retval != BLEAPI_ERROR_SUCCESS)
		abort();
}

ReturnValue BLETransportTests(pBleDevice dev)
{
	std::cout << std::endl << "==== BLE Transport tests ====" << std::endl;

	WaitForUserPresence(dev, arg_hasButton);

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

	return BLEAPI_ERROR_SUCCESS;
}

ReturnValue U2FISO7816EncodingTests(pBleDevice dev)
{
	std::
	    cout << std::endl << "==== BLE ISO7816-4 Encoding tests ====" <<
	    std::endl;
	WaitForUserPresence(dev, arg_hasButton);

	PASS(BleApiTest_TestEncodingLongAnyLength(dev));
	PASS(BleApiTest_TestEncodingLongExactLength(dev));
	PASS(BleApiTest_TestEncodingLongWrongLength(dev));

	// must do enroll before long data tests because it uses
	//   Sign command.
	BleApiTest_Enroll(dev);

	WaitForUserPresence(dev, arg_hasButton);
	PASS(BleApiTest_TestEncodingLongDataAnyLength(dev));

	WaitForUserPresence(dev, arg_hasButton);
	PASS(BleApiTest_TestEncodingLongDataExactLength(dev));

	WaitForUserPresence(dev, arg_hasButton);
	PASS(BleApiTest_TestEncodingLongDataWrongLength(dev));

	return BLEAPI_ERROR_SUCCESS;
}

ReturnValue U2FTests(pBleDevice dev)
{
	std::cout << std::
	    endl << "==== U2F Raw Message tests ====" << std::endl;
	WaitForUserPresence(dev, arg_hasButton);

	PASS(BleApiTest_GetU2FProtocolVersion(dev));
	PASS(BleApiTest_UnknownINS(dev));
	PASS(BleApiTest_BadCLA(dev));
	PASS(BleApiTest_VersionWrongLength(dev));
	PASS(BleApiTest_RegisterWrongLength(dev));

	if (arg_hasButton && !arg_preapproval)
		PASS(BleApiTest_Enroll(dev, FIDO_RESP_USERPRESENCE_REQUIRED));

	PASS(BleApiTest_Enroll(dev));

	WaitForUserPresence(dev, arg_hasButton);

	// fob with button but without pre-approval should need approval.               
	if (arg_hasButton && !arg_preapproval)
		PASS(BleApiTest_Sign(dev, FIDO_RESP_USERPRESENCE_REQUIRED));

	// Sign with check only should not produce signature.
	if (!arg_preapproval)
		PASS(BleApiTest_Sign
		     (dev, FIDO_RESP_USERPRESENCE_REQUIRED, true));

	// Sign with wrong kh.
	PASS(BleApiTest_Sign(dev, FIDO_RESP_WRONG_DATA, false, true, false));

	// Sign with wrong AppID.
	PASS(BleApiTest_Sign(dev, FIDO_RESP_WRONG_DATA, false, false, true));

	if (!arg_preapproval)
		WaitForUserPresence(dev, arg_hasButton);

	// Sign with check only should not produce signature.
	PASS(BleApiTest_Sign(dev, FIDO_RESP_USERPRESENCE_REQUIRED, true));

	uint32_t ctr1;
	PASS(ctr1 = BleApiTest_Sign(dev));
	if (!arg_preapproval)
		PASS(BleApiTest_Sign(dev, FIDO_RESP_USERPRESENCE_REQUIRED));

	WaitForUserPresence(dev, arg_hasButton);

	uint32_t ctr2;
	PASS(ctr2 = BleApiTest_Sign(dev));

	// Ctr should have incremented by 1.
	PASS(ctr2 == (ctr1 + 1));

	return BLEAPI_ERROR_SUCCESS;
}

void Usage(char *name)
{
	std::cerr << "Usage: " << name << std::endl
	    <<
	    " [ -d <device-identifier>] [-l] [-h] [-a] [-v] [-V] [-p] [-e] [-u] [-t] [-w] [-i]"
	    << std::endl
	    << "  -h : this text." << std::endl
	    << "  -a : Do not abort on failed test." << std::endl
	    << "  -v : Verbose" << std::endl
	    << "  -V : Rven more verbose" << std::endl
	    << "  -p : Pause at failed test" << std::endl
	    << "  -e : Device does preapproval when turned on" << std::endl
	    << "  -u : Disable U2F Raw Message tests. " << std::endl
	    << "  -t : Disable BLE Transport tests." << std::endl
	    << "  -i : Enable U2F ISO7816-4 encoding tests." << std::endl
	    << "  -w : Warnings are treated as errors." << std::endl
	    << "  -x : Disable encrypted connection requirement." << std::endl
	    << "  -c : Toggle ANSI colors." << std::endl
	    << "  -l : Show all known FIDO BLE devices and exit." << std::endl
	    << "  -d : Select specific FIDO BLE device." << std::endl;
	exit(-1);
}

int __cdecl main(int argc, char *argv[])
{
	int count = 1;
	pBleDevice dev = NULL;
	bool arg_ShowDevices = false;
	char *arg_DeviceIdentifier = NULL;

	while (count < argc) {
		if (!strncmp(argv[count], "-v", 2)) {
			// INFO only
			arg_Verbose |= 1;
		}
		if (!strncmp(argv[count], "-V", 2)) {
			// INFO only
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
			arg_preapproval = true;
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
			arg_iso7816 = true;
		}
		if (!strncmp(argv[count], "-w", 2)) {
			// treat warnings as errors
			arg_LethalWarn = false;
		}
		if (!strncmp(argv[count], "-l", 2)) {
			// treat warnings as errors
			arg_ShowDevices = true;
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
			arg_encryption = false;
			std::cout << "BLE connection encryption disabled." <<
			    std::endl;
		}
		if (!strncmp(argv[count], "-c", 2)) {
			arg_ansi = !arg_ansi;
		}
		++count;
	}

	try {
		pBleApi api = BleApi::CreateAPI(arg_encryption);

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
				std::cout << "  " << (*i)->
				    Identifier() << std::endl;
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
		} else {
			std::cout << "Running tests on device " <<
			    dev->Identifier() << std::endl;
		}

		/* something to do? */
		if (!(arg_transport || arg_u2f || arg_iso7816)) {
			std::cout << "Nothing to do." << std::endl;
			return 0;
		}

		/* check that link encryption is enabled */
		WARN_EQ(arg_encryption, true);

		/* do ble transport tests */
		if (arg_transport) {
			if (BLETransportTests(dev) != BLEAPI_ERROR_SUCCESS)
				return -1;
		}

		/* do the u2f tests */
		if (arg_u2f) {
			if (U2FTests(dev) != BLEAPI_ERROR_SUCCESS)
				return -1;
		}
		/* do the iso7816-4 tests */
		if (arg_iso7816) {
			if (U2FISO7816EncodingTests(dev) !=
			    BLEAPI_ERROR_SUCCESS)
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
