// TODO: Add a description about this file.

// IMPORTS

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/android_reboot.h>
#include <cutils/sockets.h>
#include <private/android_logger.h> /* private pmsg functions */
// TODO: May need to take SELinux into account here.

#include "recovery_ui/device.h"
#include "recovery_ui/stub_ui.h"
#include "recovery_ui/ui.h"

#include "usb_comms.h"


// GLOBALS

RecoveryUI* ui = nullptr;
// TODO: Add more globals as is necessary.


// FUNCTIONS

// TODO: Nothing here for now.


// MAIN

int main( int argc, char** argv )
{
	// TODO: Anything other preliminary steps?

	// Load in the device-specific recovery UI library.
	void* librecovery_ui_ext = dlopen("librecovery_ui_ext.so", RTLD_NOW);
	using MakeDeviceType = decltype(&make_device);
	MakeDeviceType make_device_func = nullptr;
	if ( librecovery_ui_ext == nullptr )
	{
		// TODO: Failed to load recovery UI library.
	}
	else
	{
		reinterpret_cast<void*&>(make_device_func) = dlsym(librecovery_ui_ext, "make_device");
		if ( make_device_func == nullptr )
		{
			// TODO: Failed to get the address of the device-specific make_device symbol.
		}
	}

	Device* device;
	if ( make_device_func == nullptr )
	{
		// Fall back to the default make_device function.
		device = make_device();
	}
	else
	{
		// Load the device-specific make_device.
		device = (*make_device_func)();
	}

	// Set up the UI.
	if ( !device->GetUI()->Init("en-US") )
	{
		device->ResetUI(new StubRecoveryUI());
	}
	ui = device->GetUI();
	ui->SetBackground(RecoveryUI::NONE);

	// TODO: Should probably set the SELinux context.

	// FIXME: TEST CODE BEGINS

	InitFunctionFS();
	android::base::SetProperty("sys.usb.config", "VERIFIER");
	android::base::WaitForProperty("sys.usb.state", "VERIFIER");

	struct stat sb;
	if (stat("/dev/usb-ffs/VERIFIER", &sb) == -1)
		ui->Print(" FAILED TO STAT /dev/usb-ffs/VERIFIER (%d)\n\n", errno);
	if (stat("/dev/usb-ffs/VERIFIER/ep0", &sb) == -1)
		ui->Print(" FAILED TO STAT ep0 (%d)\n\n", errno);
	if (stat("/dev/usb-ffs/VERIFIER/ep1", &sb) == -1)
		ui->Print(" FAILED TO STAT ep1 (%d)\n\n", errno);
	if (stat("/dev/usb-ffs/VERIFIER/ep2", &sb) == -1)
		ui->Print(" FAILED TO STAT ep2 (%d)\n\n", errno);
	if (stat("/dev/usb-ffs/VERIFIER/ep3", &sb) == -1)
		ui->Print(" FAILED TO STAT ep3 (as should be the case) (%d)\n\n", errno);

	ui->SetBackground(RecoveryUI::NO_COMMAND);
	sleep(1);
	ui->SetBackground(RecoveryUI::NONE);
	ui->ShowText(true);
	ui->Print(" TEST RECOVERY\n\n");

	int pid = fork();
	if ( pid == 0 )
	{
		char buf[256];
		ReadFromHost(buf, 256);
		ui->Print("%s", buf);
		exit(666);
	}

	ui->Print(" Rebooting to the bootloader in 5 seconds...\n\n\n\n");
	sleep(5);
	android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot,bootloader");
	//ui->Print(" Just gonna stay in an infinite loop if that's alright.\n\nHold the power button to reboot.\n\n");
	//while(true) {}	// Huh?

	// FIXME: TEST CODE ENDS

	return EXIT_SUCCESS;
}
