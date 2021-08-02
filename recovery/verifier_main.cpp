// TODO: Add a description about this file.
// TODO: Need to add MitM protections, if possible.
// TODO: Add capabilities to this process and drop root privileges, for extra security.

// IMPORTS
// TODO: Clean up unused imports.

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
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


// ==== GLOBALS ====

RecoveryUI* ui = nullptr;


// ==== FUNCTIONS ====

// TODO: Nothing here for now.


// ==== MAIN CODE ====

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
	// CMD_MNT_DEV and CMD_UMNT_DEV variables.
	int devnameLen;
	char devname[ARG_MAX_LEN];
	struct statfs statfsbuf;
	char devpath_by_name[sizeof(BLOCK_BY_NAME_PATH) + 1 + ARG_MAX_LEN];
	char fstype[16];
	char mountpath[sizeof(MOUNTPOINT_PREFIX) + ARG_MAX_LEN];
	// CMD_GET_FILE variables.
	char filepath[ARG_MAX_LEN];
	int filepathLen, fileFD;
	struct stat statbuf;
	struct file_metadata fm;
	long bytesRead, bytesLeftToRead;
	char* selinuxContext_temp = nullptr;
	char responseMetadata[1 + ARG_MAX_LEN + sizeof(struct file_metadata)];
	char responseFileBlock[1 + FILE_TRANSFER_BLOCK_SIZE];
	long bytesSent;
	long i;
	while (1)
	{
		memset(recvMsg, '\0', 1 + ARG_MAX_LEN);
		ReadFromHost(recvMsg, 1 + ARG_MAX_LEN);
		switch ( recvMsg[0] )	// First byte indicates the action to undertake.
		{
			case CMD_MNT_DEV:	// TODO: TEST THIS
				devnameLen = strnlen(recvMsg + 1, ARG_MAX_LEN-1);
				if ( devnameLen == 0 )
				{
					ui->Print(" !! No block device name provided !!\n\n");
					WriteToHost(ERR_NO_ARG, 1);
					break;
				}
				strncpy(devname, recvMsg + 1, devnameLen);
				devname[devnameLen] = '\0';
				// Disallow directory climbing - check everywhere for "../", and check for "/.." at the end.
				if ( strstr(devname, "../") || (devnameLen >= 3 && !strncmp(devname + devnameLen - 3, "/..", 3)) )
				{
					ui->Print(" !! Directory climbing detected: %s !!\n\n", devname);
					WriteToHost(ERR_DIR_CLIMBING, 1);
					break;
				}

				// Get the block device to be mounted, then get its info to determine what type we're mounting.
				// At least on my Moto G7 Play, only EXT4 and F2FS are used.
				strncpy(devpath_by_name, BLOCK_BY_NAME_PATH, sizeof(BLOCK_BY_NAME_PATH));
				strncpy(devpath_by_name + sizeof(BLOCK_BY_NAME_PATH), "/", 1);
				strncpy(devpath_by_name + sizeof(BLOCK_BY_NAME_PATH) + 1, devname, devnameLen);
				if ( statfs(devpath_by_name, &statfsbuf) == -1 )
				{
					ui->Print(" !! Failed to statfs %s: %s !!\n\n", devpath_by_name, strerror(errno));
					WriteToHost(ERR_STATFS, 1);
					break;
				}
				if ( statfsbuf.f_type == EXT4_SUPER_MAGIC )	// NOTE: f_type generally assumed to be unsigned int.
				{
					strncpy(fstype, "ext4", 16);
					fstype[4] = '\0';
				}
				else if ( statfsbuf.f_type == F2FS_SUPER_MAGIC )
				{
					strncpy(fstype, "f2fs", 16);
					fstype[4] = '\0';
				}
				else
				{
					ui->Print(" !! Device %s has unsupported filesystem %lu !!\n\n", devname, statfsbuf.f_type);
					WriteToHost(ERR_UNKNOWN_FS, 1);
					break;
				}

				strncpy(mountpath, MOUNTPOINT_PREFIX, sizeof(MOUNTPOINT_PREFIX));
				strncpy(mountpath + sizeof(MOUNTPOINT_PREFIX), "/", 1);
				strncpy(mountpath + sizeof(MOUNTPOINT_PREFIX) + 1, devname, devnameLen);

				// Create the mountpoint directory, which is assumed not to exist.
				if ( mkdir(mountpath, 0700) == -1 )
				{
					ui->Print(" !! Error creating %s: %s !!\n\n", mountpath, strerror(errno));
					WriteToHost(ERR_MKDIR, 1);
					break;
				}

				// Now let's actually mount the block device to the directory.
				// Read-only, access times not updated, no device files, and no program execution.
				// SUID and SGID is also disabled, though with exec disabled, it's kind of redundant.
				if ( mount(devpath_by_name, mountpath, fstype,
					MS_RDONLY | MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID, "") == -1 )
				{
					ui->Print(" !! Unable to mount %s: %s !!\n\n", devpath_by_name, strerror(errno));
					WriteToHost(ERR_MOUNT, 1);
					break;
				}

				break;
			case CMD_UMNT_DEV:	// TODO: TEST THIS
				devnameLen = strnlen(recvMsg + 1, ARG_MAX_LEN-1);
				if ( devnameLen == 0 )
				{
					ui->Print(" !! No block device name provided !!\n\n");
					WriteToHost(ERR_NO_ARG, 1);
					break;
				}
				strncpy(devname, recvMsg + 1, devnameLen);
				devname[devnameLen] = '\0';
				// Disallow directory climbing - check everywhere for "../", and check for "/.." at the end.
				if ( strstr(devname, "../") || (devnameLen >= 3 && !strncmp(devname + devnameLen - 3, "/..", 3)) )
				{
					ui->Print(" !! Directory climbing detected: %s !!\n\n", devname);
					WriteToHost(ERR_DIR_CLIMBING, 1);
					break;
				}
				
				strncpy(mountpath, MOUNTPOINT_PREFIX, sizeof(MOUNTPOINT_PREFIX));
				strncpy(mountpath + sizeof(MOUNTPOINT_PREFIX), "/", 1);
				strncpy(mountpath + sizeof(MOUNTPOINT_PREFIX) + 1, devname, devnameLen);

				// Unmount the filesystem.
				if ( umount(mountpath) == -1 )
				{
					ui->Print(" !! Failed to unmount %s: %s !!\n\n", mountpath, strerror(errno));
					WriteToHost(ERR_UMOUNT, 1);
					break;
				}

				// Delete the mountpoint.
				if ( rmdir(mountpath) == -1 )
				{
					ui->Print(" !! Unable to delete old mountpoint %s: %s !!\n\n", mountpath, strerror(errno));
					WriteToHost(ERR_RMDIR, 1);
					break;
				}

				break;
			case CMD_GET_FILE:	// TODO: TEST THIS
				filepathLen = strnlen(recvMsg + 1, ARG_MAX_LEN-1);
				if ( filepathLen == 0 )
				{
					ui->Print(" !! No filename provided !!\n\n");
					WriteToHost(ERR_NO_ARG, 1);
					break;
				}
				strncpy(filepath, recvMsg + 1, filepathLen);
				filepath[filepathLen] = '\0';
				// Disallow directory climbing - check everywhere for "../", and check for "/.." at the end.
				if ( strstr(filepath, "../") || (filepathLen >= 3 && !strncmp(filepath + filepathLen - 3, "/..", 3)) )
				{
					ui->Print(" !! Directory climbing detected: %s !!\n\n", filepath);
					WriteToHost(ERR_DIR_CLIMBING, 1);
					break;
				}

				// TODO: I should put the following into a separate function.

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

				memset(responseMetadata, '\0', 1 + ARG_MAX_LEN + sizeof(struct file_metadata));
				strncpy((char*)responseMetadata, FILE_METADATA, 1);
				
				// First put the metadata: filename, mode, uid, gid, mode (perm + type), size, and SELinux context.
				strncpy((char*)responseMetadata + 1, filepath, ARG_MAX_LEN-1);
				fm.uid = statbuf.st_uid;
				fm.gid = statbuf.st_gid;
				fm.mode = statbuf.st_mode;
				fm.fileSize = (S_ISREG(statbuf.st_mode) ? statbuf.st_size : 0);
				fm.contextLen = getfilecon(filepath, &selinuxContext_temp);
				if ( fm.contextLen > SELINUX_CONTEXT_MAX_LEN - 1 )
					fm.contextLen = SELINUX_CONTEXT_MAX_LEN - 1;
				if ( fm.contextLen > 0 )
				{
					strncpy(fm.selinuxContext, selinuxContext_temp, fm.contextLen);
					fm.selinuxContext[fm.contextLen] = '\0';
				}
				else
					ui->Print(" ?? Failed to get SELinux context for %s: %s ??\n\n", filepath, strerror(errno));
				memcpy((char*)responseMetadata + 1 + ARG_MAX_LEN, &fm, sizeof(struct file_metadata));

				// Send the metadata.
				bytesSent = WriteToHost(responseMetadata, 1 + ARG_MAX_LEN + sizeof(struct file_metadata));
				if ( bytesSent < 0 )
					ui->Print(" !! Failed to send metadata of %s to the host: %s !!\n\n", filepath,
							strerror(errno));
				else
					ui->Print(" Metadata of %s sent, sending contents... ", filepath);

				// Now we send the whole file itself.
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
					
					// Read each block and send it.
					strncpy(responseFileBlock, FILE_CONTENT, 1);
					bytesLeftToRead = statbuf.st_size;
					for ( i = 0; i < statbuf.st_size; i += FILE_TRANSFER_BLOCK_SIZE )
					{
						//memcpy(responseFileBlock + 1, '\0', FILE_TRANSFER_BLOCK_SIZE);
						bytesRead = read(fileFD, responseFileBlock + 1,
									(bytesLeftToRead > FILE_TRANSFER_BLOCK_SIZE
											? FILE_TRANSFER_BLOCK_SIZE
											: bytesLeftToRead));
						if ( bytesRead < 0 ) break;
						bytesLeftToRead -= bytesRead;
						bytesSent = WriteToHost(responseFileBlock, 1 + bytesRead);
						if ( bytesSent < 0 ) break;
					}
					close(fileFD);
					if ( bytesRead < 0 )
					{
						ui->Print(" !! Error while reading %s: %s !!\n\n", filepath, strerror(errno));
						WriteToHost(ERR_READ, 1);
					}
					else if ( bytesSent < 0 )
					{
						ui->Print("\n !! Failed to send %s to the host: %s !!\n\n", filepath, strerror(errno));
						// Don't bother sending an error message; the failure could be because the EP closed.
					}
					else
					{
						ui->Print(" done\n\n");
						WriteToHost(SUCCESS, 1);
					}
				}

				break;
			case CMD_SHUTDOWN:
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
