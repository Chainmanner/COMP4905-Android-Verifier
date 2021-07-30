// TODO: Add a description about this file.
// TODO: Need to add MitM protections, if possible.

// IMPORTS
// TODO: Clean up unused imports.

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

#include "verifier_constants.h"
#include "usb_comms.h"


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
	char recvMsg[1 + ARG_MAX_LEN];	// Includes the action to perform and the file to send (if applicable).
	struct stat statbuf;
	struct file_metadata fm;
	char filepath[ARG_MAX_LEN];
	int filepathLen, fileFD;
	long bytesRead;
	char* selinuxContext_temp = nullptr;
	void* response;
	int responseLen;
	int bytesSent;
	while (1)
	{
		memset(recvMsg, '\0', 1 + ARG_MAX_LEN);
		ReadFromHost(recvMsg, 1 + ARG_MAX_LEN);
		switch ( recvMsg[0] )	// First byte indicates the action to undertake.
		{
			// TODO: Mounting the partitions...
			case CMD_GET_FILE:	// TODO: TEST THIS
				filepathLen = strnlen(recvMsg + 1, ARG_MAX_LEN-1);
				if ( filepathLen == 0 )
				{
					ui->Print(" !! No filename provided !!\n\n");
					WriteToHost(ERR_NO_FILE, 1);
					break;
				}
				strncpy(filepath, recvMsg + 1, filepathLen);
				filepath[filepathLen] = '\0';
				// Disallow directory climbing - check everywhere for "../", and check for "/.." at the end.
				if ( strstr(filepath, "../") || !strncmp(filepath + filepathLen - 3, "/..", 3) )
				{
					ui->Print(" !! Directory climbing detected: %s !!\n\n", filepath);
					WriteToHost(ERR_DIR_CLIMBING, 1);
					break;
				}

				// Get the file metadata.
				if ( lstat(filepath, &statbuf) == -1 )
				{
					ui->Print(" !! Could not stat %s: %s !!\n\n", filepath, strerror(errno));
					WriteToHost(ERR_STAT, 1);
					break;
				}
				if ( statbuf.st_size > MAX_FILE_SIZE )
				{
					ui->Print(" !! %s is too big (%ld bytes; limit is %ld bytes) !!\n\n", filepath,
							statbuf.st_size, MAX_FILE_SIZE);
					WriteToHost(ERR_FILE_TOO_BIG, 1);
					break;
				}

				responseLen = 1 + ARG_MAX_LEN + sizeof(struct file_metadata)
						+ (S_ISREG(statbuf.st_mode) ? statbuf.st_size : 0);
				response = malloc(responseLen);
				strncpy((char*)response, SUCCESS, 1);
				
				// First, for the sake of request-response integrity, reply with the file path.
				strncpy((char*)response + 1, filepath, ARG_MAX_LEN-1);
				
				// Then, let's have the permission stats: st_mode, st_uid, st_gid, and the SELinux context.
				fm.uid = statbuf.st_uid;
				fm.gid = statbuf.st_gid;
				fm.mode = statbuf.st_mode;
				fm.fileSize = (S_ISREG(statbuf.st_mode) ? statbuf.st_size : 0);
				fm.contextLen = getfilecon(filepath, &selinuxContext_temp);
				if ( fm.contextLen > SELINUX_CONTEXT_MAX_LEN - 1 )
				{
					fm.contextLen = SELINUX_CONTEXT_MAX_LEN - 1;
				}
				strncpy(fm.selinuxContext, selinuxContext_temp, fm.contextLen);
				fm.selinuxContext[fm.contextLen] = '\0';
				memcpy((char*)response + 1 + ARG_MAX_LEN, &fm, sizeof(struct file_metadata));

				// After that, we include the file size and the whole file itself.
				// Obviously not applicable in the case of directories or other non-regular files.
				if ( S_ISREG(statbuf.st_mode) )
				{
					fileFD = open(filepath, O_RDONLY);
					if ( fileFD < 0 )
					{
						ui->Print(" !! Failed to open %s: %s !!\n\n", filepath, strerror(errno));
						WriteToHost(ERR_OPEN, 1);
						break;
					}
					// FIXME: This is stupid. I should be sending the file block-by-block.
					bytesRead = read(fileFD, (char*)response + 1 + ARG_MAX_LEN + sizeof(struct file_metadata),
							statbuf.st_size);
					if ( bytesRead < 0 )
					{
						ui->Print(" !! Error while reading %s: %s !!\n\n", filepath, strerror(errno));
						WriteToHost(ERR_READ, 1);
						break;
					}
					if ( bytesRead != statbuf.st_size )
					{
						// I doubt this'll ever happen, but I'm adding a check for it anyway.
						ui->Print(" !! Bytes read from %s (%ld) does not match file size (%ld) !!\n\n",
							filepath, bytesRead, statbuf.st_size);
						WriteToHost(ERR_READ_SIZE_MISMATCH, 1);
						break;
					}
					close(fileFD);
					bytesSent = WriteToHost(response, responseLen);
					if ( bytesSent < 0 )
						ui->Print(" !! Failed to send %s to the host: %s !!\n\n", filepath, strerror(errno));
					else
						ui->Print(" File %s sent to host\n\n", filepath);
				}

				break;
			case CMD_SHUTDOWN:	// TODO: TEST THIS
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
