// TODO: Add a description about this file.
// TODO: Need to add MitM protections, if possible.

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

#include <selinux/label.h>
#include <selinux/selinux.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/android_reboot.h>
#include <cutils/sockets.h>
#include <private/android_logger.h> /* private pmsg functions */

#include "recovery_ui/device.h"
#include "recovery_ui/stub_ui.h"
#include "recovery_ui/ui.h"

#include "usb_comms.h"


// PREPROCESSOR DEFS
// NOTE: The following preprocessor defs MUST ALSO be defined on the host side, for consistency.

#define FILE_PATH_MAX_LEN 512	// Not including the null terminator.
#define ERROR_MESSAGE_MAX_LEN 128	// Again, doesn't include the null terminator.

#define CMD_GET_FILE 0x2c
#define CMD_SHUTDOWN 0x4d

#define SUCCESS "\x11"
#define ERR_NO_FILE "\x22"
#define ERR_STAT "\x3e"
#define ERR_IRREGULAR_FILE "\x8f'

// Apparently the stat struct may differ across architectures, so to be safe, here's a definition with only the necessary types.
struct file_metadata {
	uid_t	uid;
	gid_t	gid;
	mode_t	mode;
	off_t	fileSize;
	size_t	contextLen;
	char selinuxContext[];
};


// GLOBALS

RecoveryUI* ui = nullptr;


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
	ui->ShowText(true);

	// TODO: Should probably set the SELinux context.

	ui->Print(" VERIFIER\n\n");

	// Sets up FunctionFS.
	// TODO: Are there phones currently in use that DON'T support ConfigFS and/or FunctionFS? If so, I need to account for them.
	if ( !InitFunctionFS() )
	{
		ui->Print(" !! Failed to init FunctionFS! Rebooting to bootloader... !!\n\n");
		android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot,bootloader");
		return -EIO;
	}
	android::base::SetProperty("sys.usb.config", "VERIFIER");
	android::base::WaitForProperty("sys.usb.state", "VERIFIER");
	ui->Print(" FunctionFS set up\n\n");

	// Device-side verifier loop. Receives and executes commands from the host.
	// TODO: Comms have no encryption or verification. Implement that!
	ui->Print(" Ready to receive commands...\n\n");
	char recvMsg[FILE_PATH_MAX_LEN + 2];	// Includes the action to perform, the file to send (if applicable), and the null end.
	struct stat statbuf;
	struct file_metadata fm;
	char filepath[FILE_PATH_MAX_LEN + 1];
	int filepathLen;
	while (1)
	{
		ReadFromHost(recvMsg, FILE_PATH_MAX_LEN + 1);
		switch ( recvMsg[0] )	// First byte indicates the action to undertake.
		{
			case CMD_GET_FILE:
				filepathLen = strnlen(recvMsg + 1, FILE_PATH_MAX_LEN);
				strncpy(filepath, recvMsg + 1, filepathLen);
				filepath[filepathLen] = '\0';

				if ( stat(filepath, &statbuf) == -1 )
				{
					ui->Print(" !! Could not stat %s: %s !!\n\n", filepath, strerror(errno));
					WriteToHost(ERR_STAT, 1);
					break;
				}
				if ( !S_ISREG(statbuf.st_mode) )	// Don't act upon whatever isn't a normal file.
				{
					ui->Print(" !! %s is not a regular file !!\n\n", filepath);
					WriteToHost(ERR_IRREGULAR_FILE, 1);
					break;
				}
				
				// First, let's have the permission stats: st_mode, st_uid, st_gid, and the SELinux context.
				// After that, we include the whole file itself.
				// TODO

				break;
			case CMD_SHUTDOWN:
				WriteToHost(SUCCESS, 1);
				ui->Print(" Rebooting to the bootloader in 5 seconds. Have a nice day!\n\n");
				sleep(5);
				android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot,bootloader");
				return EXIT_SUCCESS;
			default:
				ui->Print(" Unknown command %hhX followed by %s\n\n", recvMsg[0], recvMsg + 1);
				break;
		}
	}

	return EXIT_SUCCESS;
}
