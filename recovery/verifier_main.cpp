// TODO: Add a description about this file.
// TODO: Need to add MitM protections, if possible.

// IMPORTS
// TODO: Clean up unused imports.

#include <dirent.h>
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

#include <openssl/sha.h>

#include "recovery_ui/device.h"
#include "recovery_ui/stub_ui.h"
#include "recovery_ui/ui.h"

#include "verifier_constants.h"
#include "usb_comms.h"


// ==== PREPROCESSOR DEFS ====

// Uncomment to produce output for each file sent, but at the cost of SEVERELY degraded performance.
// Unless you're alright waiting half an hour for an operation that should take a few seconds at most, I recommend keeping this off.
//#define VERBOSE


// ==== GLOBALS ====

RecoveryUI* ui = nullptr;


// ==== FUNCTIONS ====

// Gets a file by path and sends it to the host.
// Doesn't return anything. If it fails, the host is responsible for retrying.
void SendFileToHost(int filepathLen, const char* filepath)
{
	struct stat statbuf;
	struct file_metadata fm;
	ssize_t bytesRead, bytesToRead, bytesLeftToRead;
	char* selinuxContext_temp = nullptr;
	char responseMetadata[1 + ARG_MAX_LEN + sizeof(struct file_metadata)];
	int fileFD;
	char responseFileBlock[1 + FILE_TRANSFER_BLOCK_SIZE];
	long bytesSent;
	long i;
#ifdef VERBOSE
	SHA256_CTX ctx;
	unsigned char digest[32];
#endif

	// Get the file metadata.
	if ( lstat(filepath, &statbuf) < 0 )
	{
		ui->Print(" !! Could not stat %s: %s !!\n\n", filepath, strerror(errno));
		WriteToHost(ERR_STAT, 1);
		return;
	}
	if ( statbuf.st_size > MAX_FILE_SIZE )
	{
		ui->Print(" !! %s is too big (%ld bytes; limit is %ld bytes) !!\n\n", filepath,
				statbuf.st_size, MAX_FILE_SIZE);
		WriteToHost(ERR_FILE_TOO_BIG, 1);
		return;
	}

	memset(responseMetadata, '\0', 1 + sizeof(struct file_metadata));
	strncpy((char*)responseMetadata, FILE_METADATA, 1);
	
	// First put the metadata: filename, mode, uid, gid, mode (perm + type), size, and SELinux context.
	fm.filepathLen = filepathLen;
	strncpy(fm.filepath, filepath, filepathLen);
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
	memcpy((char*)responseMetadata + 1, &fm, sizeof(struct file_metadata));

	// Send the metadata.
	bytesSent = WriteToHost(responseMetadata, 1 + sizeof(struct file_metadata));
	if ( bytesSent < 0 )
	{
		ui->Print(" !! Failed to send metadata of %s to the host: %s !!\n\n", filepath,
				strerror(errno));
		return;
	}
#ifdef VERBOSE
	ui->Print(" File %s (%lu):\n", fm.filepath, fm.filepathLen);
	ui->Print("     Size: %ld\n", fm.fileSize);
	ui->Print("     UID: %d\n", fm.uid);
	ui->Print("     GID: %d\n", fm.gid);
	ui->Print("     Mode: %o\n", fm.mode);
	ui->Print("     SELinux Context: %s (%lu)\n", fm.selinuxContext, fm.contextLen);
#endif

	// Now we send the whole file itself.
	// Obviously not applicable in the case of directories or other non-regular files.
	if ( S_ISREG(statbuf.st_mode) )
	{
		fileFD = open(filepath, O_RDONLY);
		if ( fileFD < 0 )
		{
			ui->Print(" !! Failed to open %s: %s !!\n\n", filepath, strerror(errno));
			WriteToHost(ERR_OPEN, 1);
			return;
		}
		
		// Read each block and send it.
		// NOTE: Do NOT change the following without also changing it in the host code!
		//	 You risk desynchronization if you don't.
		responseFileBlock[0] = FILE_CONTENT[0];
		bytesLeftToRead = statbuf.st_size;
#ifdef VERBOSE
		SHA256_Init(&ctx);
#endif
		for ( i = 0; i < statbuf.st_size; i += FILE_TRANSFER_BLOCK_SIZE )
		{
			//memcpy(responseFileBlock + 1, '\0', FILE_TRANSFER_BLOCK_SIZE);
			bytesToRead = (bytesLeftToRead > FILE_TRANSFER_BLOCK_SIZE
								? FILE_TRANSFER_BLOCK_SIZE
								: bytesLeftToRead);
			if ( bytesToRead == 0 )
				break;
			bytesRead = read(fileFD, responseFileBlock + 1, bytesToRead);
			if ( bytesRead < 0 ) break;
			bytesLeftToRead -= bytesRead;
			bytesSent = WriteToHost(responseFileBlock, 1 + bytesRead);
			if ( bytesSent < 0 ) break;
#ifdef VERBOSE
			SHA256_Update(&ctx, responseFileBlock + 1, bytesRead);
#endif
		}
		close(fileFD);
		if ( bytesRead < 0 )
		{
			ui->Print(" !! Error while reading %s: %s !!\n\n", filepath, strerror(errno));
			WriteToHost(ERR_READ, 1);
			return;
		}
		else if ( bytesSent < 0 )
		{
			ui->Print("\n !! Failed to send %s to the host: %s !!\n\n", filepath, strerror(errno));
			// Don't bother sending an error message; the failure could be because the EP closed.
			return;
		}
#ifdef VERBOSE
		SHA256_Final(digest, &ctx);
		ui->Print("     SHA256: ");
		for ( i = 0; i < 32; i++ )
			ui->Print("%02hhx", digest[i]);
		ui->Print("\n\n");
#endif
	}
	WriteToHost(SUCCESS, 1);
}

// Sends ALL entities under a directory, recursively for subdirectories.
// Returns the number of files sent.
int SendAllUnderDir(int dirpathLen, const char* dirpath)
{
	DIR* curDir;
	dirent* curDirEnt;
	size_t curDirEnt_nameLen;
	char curPath[NAME_MAX];
	size_t curPath_len;
	int dirEntsSent = 0;

	curDir = opendir(dirpath);
	curDirEnt = readdir(curDir);
	while ( curDirEnt != NULL )
	{
		curDirEnt_nameLen = strnlen(curDirEnt->d_name, 255);

		// Ignore the pointers to the current and parent directories.
		if ( !strncmp(curDirEnt->d_name, "..", curDirEnt_nameLen) || !strncmp(curDirEnt->d_name, ".", curDirEnt_nameLen) )
		{
			curDirEnt = readdir(curDir);
			continue;
		}

		// Get the full path of this file.
		snprintf(curPath, NAME_MAX, "%s/%s", dirpath, curDirEnt->d_name);
		curPath_len = strnlen(curPath, NAME_MAX);

		// Send the current dirent to the host, and if it's a directory, recurse into it as well.
		SendFileToHost(curPath_len, curPath);
		dirEntsSent++;
		if ( curDirEnt->d_type == DT_DIR )
			dirEntsSent += SendAllUnderDir(curPath_len, curPath);

		curDirEnt = readdir(curDir);
	}

	// Since the function's recursive, don't send the SUCCESS byte here. Send it after the topmost function call is done.
	return dirEntsSent;
}


// ==== MAIN CODE ====

int main(int argc, char** argv)
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
	ssize_t bytesRead;
	char recvMsg[1 + ARG_MAX_LEN];	// Includes the action to perform and the file to send (if applicable).
	// CMD_MNT_DEV and CMD_UMNT_DEV variables.
	int devnameLen;
	char devname[ARG_MAX_LEN];
	char devpath_by_name[sizeof(BLOCK_BY_NAME_PATH) + 1 + ARG_MAX_LEN];
	char mountpath[sizeof(MOUNTPOINT_PREFIX) + 1 + ARG_MAX_LEN];
	// CMD_GET_FILE variables.
	char filepath[ARG_MAX_LEN];
	int filepathLen;
	// CMD_GET_ALL variables.
	char dirpath[ARG_MAX_LEN];
	int dirpathLen;
	while (1)
	{
		memset(recvMsg, '\0', 1 + ARG_MAX_LEN);
		bytesRead = ReadFromHost(recvMsg, 1 + ARG_MAX_LEN);
		if ( bytesRead < 0 )
		{
			ui->Print("!! Error while receiving a command: %s !!\n\n", strerror(errno));
			ui->Print("!! Connection may be done for - REBOOTING TO BOOTLOADER !!\n\n");
			sleep(5);
			android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot,bootloader");
			return -1;
		}
		//ui->Print(" Command: %hhX | Arg: %s\n", recvMsg[0], recvMsg + 1);
		switch ( recvMsg[0] )	// First byte indicates the action to undertake.
		{
			// Mounts a block device.
			case CMD_MNT_DEV:
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

				ui->Print(" Mounting %s...\n\n", devname);

				// Get the path of the block device to be mounted, and the path at which to mount it.
				snprintf(devpath_by_name, sizeof(devpath_by_name), "%s/%s", BLOCK_BY_NAME_PATH, devname);
				snprintf(mountpath, sizeof(mountpath), "%s/%s", MOUNTPOINT_PREFIX, devname);

				// Create the mountpoint directory, which is assumed not to exist.
				// NOTE: No exception made for EEXIST. This directory should not have existed in the first place.
				if ( mkdir(mountpath, 0700) < 0 )
				{
					ui->Print(" !! Error creating %s: %s !!\n\n", mountpath, strerror(errno));
					WriteToHost(ERR_MKDIR, 1);
					break;
				}

				// Now let's actually mount the block device to the directory.
				// Read-only, access times not updated, no device files, and no program execution.
				// SUID and SGID is also disabled, though with exec disabled, it's kind of redundant.
				// NOTE: For non-encrypted partitions, Android uses EXT4. For encrypted partitions, it uses F2FS, but
				//	 there's no point in checking encrypted user data.
				if ( mount(devpath_by_name, mountpath, "ext4",
					MS_RDONLY | MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID, "") < 0 )
				{
					ui->Print(" !! Unable to mount %s: %s !!\n\n", devpath_by_name, strerror(errno));
					rmdir(mountpath);
					WriteToHost(ERR_MOUNT, 1);
					break;
				}

				WriteToHost(SUCCESS, 1);

				break;

			// Unmounts a block device.
			case CMD_UMNT_DEV:
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

				ui->Print(" Unmounting %s...\n\n", devname);
				
				snprintf(mountpath, sizeof(mountpath), "%s/%s", MOUNTPOINT_PREFIX, devname);

				// Unmount the filesystem.
				if ( umount(mountpath) < 0 )
				{
					ui->Print(" !! Failed to unmount %s: %s !!\n\n", mountpath, strerror(errno));
					WriteToHost(ERR_UMOUNT, 1);
					break;
				}

				// Delete the mountpoint.
				if ( rmdir(mountpath) < 0 )
				{
					ui->Print(" !! Unable to delete old mountpoint %s: %s !!\n\n", mountpath, strerror(errno));
					WriteToHost(ERR_RMDIR, 1);
					break;
				}

				WriteToHost(SUCCESS, 1);

				break;

			// Gets a file's metadata and data, and sends both to the host.
			case CMD_GET_FILE:
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

				SendFileToHost(filepathLen, filepath);

				break;

			case CMD_GET_ALL:	// TODO: TEST THIS
				dirpathLen = strnlen(recvMsg + 1, ARG_MAX_LEN-1);
				if ( dirpathLen == 0 )
				{
					ui->Print(" !! No directory provided !!\n\n");
					WriteToHost(ERR_NO_ARG, 1);
					break;
				}
				strncpy(dirpath, recvMsg + 1, dirpathLen);
				dirpath[dirpathLen] = '\0';
				// Disallow directory climbing - check everywhere for "../", and check for "/.." at the end.
				if ( strstr(dirpath, "../") || (dirpathLen >= 3 && !strncmp(dirpath + dirpathLen - 3, "/..", 3)) )
				{
					ui->Print(" !! Directory climbing detected: %s !!\n\n", filepath);
					WriteToHost(ERR_DIR_CLIMBING, 1);
					break;
				}

				SendAllUnderDir(dirpathLen, dirpath);
				WriteToHost(SUCCESS, 1);	// Host is expecting a final success message to tell it to stop.

				break;

			// Reboots the device to the bootloader.
			case CMD_SHUTDOWN:
				// TODO: Close the open file descriptors.
				ui->Print("\n\n Rebooting to the bootloader in 5 seconds. Have a nice day!\n\n");
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
