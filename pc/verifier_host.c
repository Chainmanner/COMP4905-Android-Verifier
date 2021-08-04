// TODO: Add comments.
// TODO: Implement device-to-host encryption.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include <linux/usbdevice_fs.h>
#include <linux/usb/ch9.h>

#include "verifier_constants.h"


// ==== PREPROCESSOR DEFS ====

// The vendor ID and product ID specified below MUST match the corresponding vendor/product IDs of the verifier, seen in
// recovery/etc/init.rc file of the Android recovery (under the sections where "on property:sys.usb.config=VERIFIER ..." is specified).
#define VERIFIER_VENDOR 0xE666
#define VERIFIER_PRODUCT 0xE666

#define USB_TRANSFER_LIMIT (16 * 1024)
#define TIMEOUT 0


// ==== FUNCTIONS ====

// Reads at most numBytes from the device into inBuf.
// Returns the number of bytes read, or -1 if an error occurred (and also prints the error).
ssize_t ReadFromDevice(int descFD, int epInID, void* inBuf, size_t numBytes)
{
	char* inBuf_curPtr = (char*)inBuf;
	size_t bytesLeftToRead = numBytes;
	size_t bytesToRead;
	ssize_t bytesRead;
	ssize_t bytesReadTotal = 0;
	struct usbdevfs_bulktransfer bulk;

	while ( bytesLeftToRead > 0 )
	{
		bytesToRead = bytesLeftToRead < USB_TRANSFER_LIMIT ? bytesLeftToRead : USB_TRANSFER_LIMIT;
		bulk.ep = epInID;
		bulk.len = bytesToRead;
		bulk.data = inBuf_curPtr;
		bulk.timeout = TIMEOUT;
		bytesRead = ioctl(descFD, USBDEVFS_BULK, &bulk);
		if ( bytesRead < 0 )
		{
			printf("!! Error reading data from device: %s !!\n", strerror(errno));
			return -1;
		}

		bytesReadTotal += bytesRead;
		bytesLeftToRead -= bytesRead;
		inBuf_curPtr += bytesRead;
		if ( bytesRead < bytesToRead )	// Transmission ended earlier than expected.
			break;
	}

	return bytesReadTotal;
}

// Writes at most numBytes from outBuf to the device.
// Returns the number of bytes written, or -1 if an error occurred (and also prints the error).
ssize_t WriteToDevice(int descFD, int epOutID, const void* outBuf, size_t numBytes)
{
	char* outBuf_curPtr = (char*)outBuf;
	size_t bytesLeftToWrite = numBytes;
	size_t bytesToWrite;
	ssize_t bytesWritten;
	ssize_t bytesWrittenTotal = 0;
	struct usbdevfs_bulktransfer bulk;

	while ( bytesLeftToWrite > 0 )
	{
		bytesToWrite = bytesLeftToWrite < USB_TRANSFER_LIMIT ? bytesLeftToWrite : USB_TRANSFER_LIMIT;
		bulk.ep = epOutID;
		bulk.len = bytesToWrite;
		bulk.data = outBuf_curPtr;
		bulk.timeout = TIMEOUT;
		bytesWritten = ioctl(descFD, USBDEVFS_BULK, &bulk);
		if ( bytesWritten < 0 )
		{
			printf("!! Error writing data to device: %s !!\n", strerror(errno));
			return -1;
		}

		bytesWrittenTotal += bytesWritten;
		bytesLeftToWrite -= bytesWritten;
		outBuf_curPtr += bytesWritten;
		if ( bytesWritten < bytesToWrite )
			break;
	}

	return bytesWrittenTotal;
}

// Gets the string that corresponds to an error response byte.
// Since you can't scroll through the device's log, this should be printed on the host's end in case the user misses something.
const char* GetErrorString(char code)
{
	char code_str[2];
	code_str[0] = code;
	code_str[1] = '\0';

	// TODO: Change these to directly compare the first character, e.g. code = ERR_NO_ARG[0].
	if ( !strncmp(code_str, ERR_NO_ARG, 1) )
		return "No argument provided";
	if ( !strncmp(code_str, ERR_DIR_CLIMBING, 1) )
		return "Directory traversal detected";
	if ( !strncmp(code_str, ERR_STAT, 1) )
		return "stat(2) failed";
	if ( !strncmp(code_str, ERR_MKDIR, 1) )
		return "mkdir(2) failed";
	if ( !strncmp(code_str, ERR_MOUNT, 1) )
		return "mount(2) failed";
	if ( !strncmp(code_str, ERR_UMOUNT, 1) )
		return "umount(2) failed";
	if ( !strncmp(code_str, ERR_RMDIR, 1) )
		return "rmdir(2) failed";
	if ( !strncmp(code_str, ERR_FILE_TOO_BIG, 1) )
		return "Directory traversal detected";
	if ( !strncmp(code_str, ERR_OPEN, 1) )
		return "open(2) failed";
	if ( !strncmp(code_str, ERR_READ, 1) )
		return "read(2) failed";
	if ( !strncmp(code_str, SUCCESS, 1) )
		return "<success>";
	if ( code == FILE_CONTENT[0] )
		return "Transmission not yet done";

	return "<string not available for this error code>";
}

// Mounts a partition on the device by name.
// On success, the partition is mounted to /mnt/<part-name>, where <part-name> is the partition's name in /dev/block/by-name (or
// whatever BLOCK_BY_NAME_PATH is set to), and returns 0.
// On failure, returns -1.
int MountPartition(int descFD, int epInID, int epOutID, const char* devname)
{
	char cmd[1 + ARG_MAX_LEN];
	char response[2];
	size_t devnameLen;

	devnameLen = strnlen(devname, ARG_MAX_LEN-1);
	if ( devnameLen == ARG_MAX_LEN-1 )
	{
		printf("!! Device name %s too long - aborting mount !!\n", devname);
		return -1;
	}
	cmd[0] = CMD_MNT_DEV;
	strncpy(cmd + 1, devname, devnameLen);
	cmd[1 + devnameLen] = '\0';

	if ( WriteToDevice(descFD, epOutID, cmd, 1 + devnameLen + 1) < 0 )
		return -1;
	if ( ReadFromDevice(descFD, epInID, response, 1) < 0 )
		return -1;
	response[1] = '\0';
	if ( !strncmp(response, SUCCESS, 1) )
	{
		printf("-- Device %s mounted successfully to %s/%s --\n", devname, MOUNTPOINT_PREFIX, devname);
		return 0;
	}

	printf("!! Error mounting %s: %s !!\n", devname, GetErrorString(response[0]));
	return -1;
}

// Unmounts a partition on the device by name (same name as was used to mount it).
// On success, partition is unmounted; old mountpoint is deleted; and this function returns 0.
// On failure, -1 is returned.
int UnmountPartition(int descFD, int epInID, int epOutID, const char* devname)
{
	char cmd[1 + ARG_MAX_LEN];
	char response[2];
	size_t devnameLen;
	
	devnameLen = strnlen(devname, ARG_MAX_LEN-1);
	if ( devnameLen == ARG_MAX_LEN-1 )
	{
		printf("!! Device name %s too long - aborting unmount !!\n", devname);
		return -1;
	}
	cmd[0] = CMD_UMNT_DEV;
	strncpy(cmd + 1, devname, devnameLen);
	cmd[1 + devnameLen] = '\0';
	
	if ( WriteToDevice(descFD, epOutID, cmd, 1 + devnameLen) < 0 )
		return -1;
	if ( ReadFromDevice(descFD, epInID, response, 1) < 0 )
		return -1;
	response[1] = '\0';
	if ( !strncmp(response, SUCCESS, 1) )
	{
		printf("-- Device %s unmounted --\n", devname);
		return 0;
	}

	printf("!! Error unmounting %s: %s !!\n", devname, GetErrorString(response[0]));
	return -1;
}

// Sends the signal to reboot the device to the bootloader.
int RebootDevice(int descFD, int epOutID)
{
	char cmd[1];
	cmd[0] = CMD_SHUTDOWN;
	if ( WriteToDevice(descFD, epOutID, cmd, 1) < 0 )
		return -1;
	printf("-- Reboot-to-bootloader signal sent to device --\n");
	return 0;
}

#if 0
// Requests a file and saves its contents to disk as the data is received.
// Returns 0 on success, -1 on failure.
// NOTE: No use for this in the final project. But I'll keep it, just in case I'll need it again.
int GetFileAndSave(int descFD, int epInID, int epOutID, const char* reqPath, const char* savePath, struct file_metadata* fm)
{
	char cmd[1 + ARG_MAX_LEN];
	int reqPathLen;
	char responseMetadata[1 + sizeof(struct file_metadata)];
	char responseFileBlock[1 + FILE_TRANSFER_BLOCK_SIZE];
	size_t fileSize;
	int saveFileFD;
	ssize_t bytesRead;
	size_t bytesToRead;
	size_t bytesLeftToRead;
	size_t bytesReadTotal = 0;
	size_t i;

	cmd[0] = CMD_GET_FILE;
	reqPathLen = strnlen(reqPath, ARG_MAX_LEN-1);
	if ( reqPathLen == ARG_MAX_LEN-1 )
	{
		printf("!! Filename %s too long - aborting file request !!\n", reqPath);
		return -1;
	}
	strncpy(cmd + 1, reqPath, reqPathLen);
	cmd[1 + reqPathLen] = '\0';

	// Send the command and get the file metadata.
	if ( WriteToDevice(descFD, epOutID, cmd, 1 + reqPathLen) < 0 )
		return -1;
	if ( ReadFromDevice(descFD, epInID, responseMetadata, 1 + sizeof(struct file_metadata)) < 0 )
		return -1;
	if ( strncmp(responseMetadata, FILE_METADATA, 1) != 0 )
	{
		printf("!! Error receiving metadata for %s: %s !!\n", reqPath, GetErrorString(responseMetadata[0]));
		return -1;
	}
	memcpy(fm, responseMetadata + 1, sizeof(struct file_metadata));

	if ( S_ISREG(fm->mode) )
	{
		saveFileFD = open(savePath, O_WRONLY | O_CREAT, 0600);
		if ( saveFileFD < 0 )
		{
			printf("!! Error opening %s for writing: %s !!\n", savePath, strerror(errno));
			return -1;
		}
		
		// We need to receive the bytes from the device EXACTLY as they are sent, or else we could get a deadlock.
		// NOTE: Do NOT change the following without also changing it in the device code!
		//	 You risk desynchronization if you don't.
		fileSize = (size_t)fm->fileSize;
		bytesLeftToRead = fileSize;
		for ( i = 0; i < fileSize; i += FILE_TRANSFER_BLOCK_SIZE )
		{
			bytesToRead = (bytesLeftToRead > FILE_TRANSFER_BLOCK_SIZE ? FILE_TRANSFER_BLOCK_SIZE : bytesLeftToRead);
			if ( bytesToRead == 0 )
				break;
			bytesRead = ReadFromDevice(descFD, epInID, responseFileBlock, 1 + bytesToRead);
			if ( bytesRead < 0 ) break;
			bytesLeftToRead -= bytesRead - 1;
			bytesReadTotal += bytesRead - 1;
			write(saveFileFD, responseFileBlock + 1, bytesRead - 1);
		}
		close(saveFileFD);
		if ( bytesRead < 0 )	// Explanation for failure already provided by ReadFromDevice().
			return -1;
	}

	if ( ReadFromDevice(descFD, epInID, responseFileBlock, 1) < 0 )	// Get the success message to confirm that we're done.
		return -1;
	if ( responseFileBlock[0] != SUCCESS[0] )
	{
		printf("!! Error receiving data for %s: %s !!\n", reqPath, GetErrorString(responseFileBlock[0]));
		return -1;
	}
	if ( bytesReadTotal != fileSize )	// Should never happen, but let's try to detect premature termination.
	{
		printf("!! Mismatch between stated file size (%lu) and bytes received (%lu) !!\n", fileSize, bytesReadTotal);
		return -1;
	}

	printf("-- Received file %s and saved it to disk as %s --\n", reqPath, savePath);
	return 0;
}
#endif

// Receives a file's metadata from the device, and generates a SHA256 digest of its contents as they are received.
// Returns 0 on success, -1 on failure, and 1 if a success response was received when file metadata was expected.
// WARNING: digest MUST be at least 32 bytes long or else a buffer overflow will happen!
int ReceiveFileMetaAndHash(int descFD, int epInID, struct file_metadata* fm, unsigned char* digest)
{
	char responseMetadata[1 + sizeof(struct file_metadata)];
	char responseFileBlock[1 + FILE_TRANSFER_BLOCK_SIZE];
	size_t fileSize;
	ssize_t bytesRead;
	size_t bytesToRead;
	size_t bytesLeftToRead;
	size_t bytesReadTotal = 0;
	size_t i;
	SHA256_CTX ctx;

	if ( ReadFromDevice(descFD, epInID, responseMetadata, 1 + sizeof(struct file_metadata)) < 0 )
		return -1;

	if ( responseMetadata[0] == SUCCESS[0] )
		return 1;
	else if ( responseMetadata[0] != FILE_METADATA[0] )
	{
		printf("!! Error receiving metadata: %s !!\n", GetErrorString(responseMetadata[0]));
		return -1;
	}
	memcpy(fm, responseMetadata + 1, sizeof(struct file_metadata));

	if ( S_ISREG(fm->mode) )
	{
		// We need to receive the bytes from the device EXACTLY as they are sent, or else we could get a deadlock.
		// NOTE: Do NOT change the following without also changing it in the device code!
		//	 You risk desynchronization if you don't.
		fileSize = (size_t)fm->fileSize;
		bytesLeftToRead = fileSize;
		SHA256_Init(&ctx);
		for ( i = 0; i < fileSize; i += FILE_TRANSFER_BLOCK_SIZE )
		{
			bytesToRead = (bytesLeftToRead > FILE_TRANSFER_BLOCK_SIZE ? FILE_TRANSFER_BLOCK_SIZE : bytesLeftToRead);
			if ( bytesToRead == 0 )
				break;
			bytesRead = ReadFromDevice(descFD, epInID, responseFileBlock, 1 + bytesToRead);
			if ( bytesRead < 0 ) break;
			bytesLeftToRead -= bytesRead - 1;
			bytesReadTotal += bytesRead - 1;
			SHA256_Update(&ctx, responseFileBlock + 1, bytesRead - 1);
		}
		SHA256_Final(digest, &ctx);
		if ( bytesRead < 0 )	// Explanation for failure already provided by ReadFromDevice().
			return -1;
	}

	if ( ReadFromDevice(descFD, epInID, responseFileBlock, 1) < 0 )	// Get the success message to confirm that we're done.
		return -1;
	if ( responseFileBlock[0] != SUCCESS[0] )
	{
		printf("!! Error receiving data for %s: %s !!\n", fm->filepath, GetErrorString(responseFileBlock[0]));
		return -1;
	}
	if ( S_ISREG(fm->mode) && bytesReadTotal != fileSize )	// Should never happen, but let's try to detect premature termination.
	{
		printf("!! Mismatch between stated file size (%lu) and bytes received (%lu) !!\n", fileSize, bytesReadTotal);
		return -1;
	}

	return 0;
}

// Requests a file from the device, gets its metadata, and if it's a regular file, generates a SHA256 digest of its contents.
// Not to be confused with ReceiveFileMetaAndHash(), which only handles reception. Returns 0 on success, -1 on failure.
// WARNING: digest MUST be at least 32 bytes long or else a buffer overflow will happen!
int GetFileMetaAndHash(int descFD, int epInID, int epOutID, const char* reqPath, struct file_metadata* fm, unsigned char* digest)
{
	char cmd[1 + ARG_MAX_LEN];
	int reqPathLen;
	int ret;
	int i;

	cmd[0] = CMD_GET_FILE;
	reqPathLen = strnlen(reqPath, ARG_MAX_LEN-1);
	if ( reqPathLen == ARG_MAX_LEN-1 )
	{
		printf("!! Filename %s too long - aborting file request !!\n", reqPath);
		return -1;
	}
	strncpy(cmd + 1, reqPath, reqPathLen);
	cmd[1 + reqPathLen] = '\0';

	// Send the command and hand the reception off to ReceiveFileMetaAndHash().
	if ( WriteToDevice(descFD, epOutID, cmd, 1 + reqPathLen) < 0 )
		return -1;

	ret = ReceiveFileMetaAndHash(descFD, epInID, fm, digest);
	if ( ret == 0 )
	{
		printf("-- Received file %s having SHA256 digest ", reqPath);
		for ( i = 0; i < 32; i++ ) printf("%02hhx", digest[i]);
		printf(" --\n");
	}
	return ret;
}

// Gets the metadata and hashes of all files under a directory, as deep as necessary.
// TODO: Also write the received file and metadata.
// Returns 0 on success, -1 on failure.
int GetAllFilesUnderDir(int descFD, int epInID, int epOutID, const char* reqPath)
{
	char cmd[1 + ARG_MAX_LEN];
	int reqPathLen;
	int ret;
	struct file_metadata fm;
	unsigned char digest[32];

	cmd[0] = CMD_GET_ALL;
	reqPathLen = strnlen(reqPath, ARG_MAX_LEN-1);
	if ( reqPathLen == ARG_MAX_LEN-1 )
	{
		printf("!! Filename %s too long - aborting file request !!\n", reqPath);
		return -1;
	}
	strncpy(cmd + 1, reqPath, reqPathLen);
	cmd[1 + reqPathLen] = '\0';

	if ( WriteToDevice(descFD, epOutID, cmd, 1 + reqPathLen) < 0 )
		return -1;

	do
	{
		ret = ReceiveFileMetaAndHash(descFD, epInID, &fm, digest);
		// FIXME: == TEST CODE BEGINS ==
		printf("file: %s (len = %lu)\n\tuid: %d\n\tgid: %d\n\tmode: %o\n\tcontext: %s\n\tsha256: ",
			fm.filepath, fm.filepathLen, fm.uid, fm.gid, fm.mode, fm.selinuxContext);
		for ( int i = 0; i < 32; i++ ) printf("%02hhx", digest[i]);
		printf("\n");
		memset(&fm, '\0', sizeof(struct file_metadata));
		memset(digest, '\0', 32);
		// FIXME: == TEST CODE ENDS ==
	}
	while ( ret == 0 );
	return ret;
}


// ==== MAIN CODE ====

int main(int argc, char** argv)
{
	// == VARIABLES ==

	int i;

	ssize_t bytesRead;
	DIR* dirPtr;
	struct dirent* curDirEnt;
	char curVendorPath[64], curProductPath[64];
	int vendorFD, productFD;
	char vendor_char[5], product_char[5];
	unsigned int vendor, product;

	char busNumPath[64], devNumPath[64];
	int busFD, devFD;
	char bus_char[4], dev_char[4];
	unsigned int bus, dev;
	char devPath[64];

	int descFD;
	//char desc[1024];
	int ifID, epInID, epOutID;
	// TODO: Add more function-specific variables as is necessary.

	// == CODE ==

	// First step is to find the device with the vendor and product IDs of the verifier.
	// We'll use sysfs to do this, since we only need to read data.
	printf("-- Searching for verifier USB device... --\n");
	dirPtr = opendir("/sys/bus/usb/devices");
	if ( !dirPtr )
	{
		printf("!! Couldn't open /sys/bus/usb/devices: %s !!\n", strerror(errno));
		return -1;
	}
	// Sift through all sysfs USB device entries.
	while ( 1 )
	{
		curDirEnt = readdir(dirPtr);
		if ( curDirEnt == NULL )
		{
			printf("!! Verifier (vendor ID %X, product ID %X) not found !!\n", VERIFIER_VENDOR, VERIFIER_PRODUCT);
			return -1;
		}

		// Get the vendor and product IDs of this USB device.
		snprintf(curVendorPath, sizeof(curVendorPath), "/sys/bus/usb/devices/%s/idVendor", curDirEnt->d_name);
		snprintf(curProductPath, sizeof(curProductPath), "/sys/bus/usb/devices/%s/idProduct", curDirEnt->d_name);
		vendorFD = open(curVendorPath, O_RDONLY);
		productFD = open(curProductPath, O_RDONLY);
		if ( vendorFD < 0 || productFD < 0 )	// Just skip this entry if we can't get its vendor ID or product ID.
			continue;
		bytesRead = read(vendorFD, vendor_char, 4);
		if ( bytesRead < 0 ) continue;
		bytesRead = read(productFD, product_char, 4);
		if ( bytesRead < 0 ) continue;
		close(vendorFD);
		close(productFD);
		vendor_char[4] = '\0';
		product_char[4] = '\0';

		// If this device has the vendor/product ID pair of the verifier, get the bus and device numbers and derive its path
		// in devfs so that we can access the USB device.
		vendor = (unsigned int)strtol(vendor_char, NULL, 16);
		product = (unsigned int)strtol(product_char, NULL, 16);
		if ( vendor == VERIFIER_VENDOR && product == VERIFIER_PRODUCT )
		{
			printf("-- Found USB device with verifier vendor/product IDs (%s), getting devfs path... --\n",
				curDirEnt->d_name);
			snprintf(busNumPath, sizeof(busNumPath), "/sys/bus/usb/devices/%s/busnum", curDirEnt->d_name);
			snprintf(devNumPath, sizeof(devNumPath), "/sys/bus/usb/devices/%s/devnum", curDirEnt->d_name);
			busFD = open(busNumPath, O_RDONLY);
			if ( busFD < 0 )
			{
				printf("!! Unable to open %s: %s !!\n", busNumPath, strerror(errno));
				return -1;
			}
			devFD = open(devNumPath, O_RDONLY);
			if ( devFD < 0 )
			{
				printf("!! Unable to open %s: %s !!\n", devNumPath, strerror(errno));
				return -1;
			}

			bytesRead = read(busFD, bus_char, 3);
			if ( bytesRead < 0 )
			{
				printf("!! Unable to read bus number: %s !!\n", strerror(errno));
				return -1;
			}
			bytesRead = read(devFD, dev_char, 3);
			if ( bytesRead < 0 )
			{
				printf("!! Unable to read device number: %s !!\n", strerror(errno));
				return -1;
			}
			close(busFD);
			close(devFD);

			bus = (unsigned int)strtol(bus_char, NULL, 10);
			dev = (unsigned int)strtol(dev_char, NULL, 10);
			snprintf(devPath, sizeof(devPath), "/dev/bus/usb/%03d/%03d", bus, dev);
			printf("-- Devfs path: %s --\n", devPath);

			break;
		}
	}

	// Open the USB device for reading and writing, and get the descriptor.
	descFD = open(devPath, O_RDWR);
	if ( descFD < 0 )
	{
		printf("!! Failed to open %s for reading/writing: %s !!\n", devPath, strerror(errno));
		printf("!! (NOTE: If it's a 'Permission denied' error, make sure the proper udev rules are in place; !!\n");
		printf("!! DO NOT TAKE THE EASY ROUTE AND RUN THIS PROGRAM AS ROOT) !!\n");
		return -1;
	}
	//descSize = read(descFD, desc, sizeof(desc));
	printf("-- Opened %s for reading/writing --\n", devPath);

	// We already know the USB interface ID, input endpoint ID, and output endpoint ID. They're defined in verifier_constants.h.
	// Knowing those, we can claim the USB interface.
	ifID = INTERFACE_NUMBER;
	epInID = IN_ADDR;
	epOutID = OUT_ADDR;
	if ( ioctl(descFD, USBDEVFS_CLAIMINTERFACE, &ifID) < 0 )
	{
		printf("!! Unable to claim USB interface %d: %s !!\n", ifID, strerror(errno));
		close(descFD);
		return -1;
	}

	// FIXME: ==== TEST CODE ====

	GetAllFilesUnderDir(descFD, epInID, epOutID, "/system");

	/*struct file_metadata fm;
	unsigned char digest1[32];
	unsigned char digest2[32];
	unsigned char digest3[32];
	GetFileMetaAndHash(descFD, epInID, epOutID, "/bin/recovery", &fm, digest1);
	GetFileMetaAndHash(descFD, epInID, epOutID, "/init.rc", &fm, digest2);
	GetFileMetaAndHash(descFD, epInID, epOutID, "/init.rc", &fm, digest3);*/

	/*MountPartition(descFD, epInID, epOutID, "system_a");
	MountPartition(descFD, epInID, epOutID, "system_b");
	MountPartition(descFD, epInID, epOutID, "vendor_a");
	MountPartition(descFD, epInID, epOutID, "vendor_b");
	UnmountPartition(descFD, epInID, epOutID, "system_a");
	UnmountPartition(descFD, epInID, epOutID, "system_b");
	UnmountPartition(descFD, epInID, epOutID, "vendor_a");
	UnmountPartition(descFD, epInID, epOutID, "vendor_b");*/

	RebootDevice(descFD, epOutID);

	// FIXME: ==== TEST CODE ENDS ====

	if ( ioctl(descFD, USBDEVFS_RELEASEINTERFACE, &ifID) < 0 )	// If this fails, continue anyway, but report the error.
		printf("!! Unable to release USB interface %d: %s !!\n", ifID, strerror(errno));
	close(descFD);
	return 0;
}
