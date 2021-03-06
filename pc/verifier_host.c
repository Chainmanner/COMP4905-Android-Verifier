// COMP4905 - Honours Project, Carleton University
// Gabriel Valachi (101068875)
/*
	Copyright (C) 2021	Gabriel Valachi

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// This is the main file for the verifier. After the recovery image is sideloaded to the Android phone, the verifier connects to it and
// issues commands to verify the phone.
// To set the partitions to be verified, you need to modify NUM_PARTITIONS, partitions_to_check, NUM_NONFS_PARTITIONS, and
// nonfs_partitions_to_check, and then recompile the verifier.
//	NUM_PARTITIONS is the number of partitions with filesystems to check.
//	partitions_to_check is the list of partitions with filesystems to check.
//	NUM_NONFS_PARTITIONS is the number of partitions without filesystems to check.
//	nonfs_partitions_to_check is the list of partitions without filesystems to check.
// To compile the verifier using GCC, run this command:
//	gcc -lcrypto -o verifier usb_comms_host.c verifier_host.c

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include <linux/usbdevice_fs.h>
#include <linux/usb/ch9.h>

#include <openssl/evp.h>

#include "verifier_constants.h"
#include "usb_comms_host.h"


// ==== PREPROCESSOR DEFS ====

#define HASHFUNC EVP_blake2b512()	// The hash function to use.
#define HASHLEN 64			// The length of the hash function's digest in BYTES.

// CHANGE THESE AND RECOMPILE THE VERIFIER
#define NUM_PARTITIONS 0
const char* partitions_to_check[] = {	// NOTE: Filesystems of the provided partitions MUST be EXT4 or F2FS.
};

// CHANGE THESE AND RECOMPILE THE VERIFIER
#define NUM_NONFS_PARTITIONS 0
const char* nonfs_partitions_to_check[] = {	// These partitions don't have a valid filesystem, so we check them in their entirety.
};


// ==== FUNCTIONS ====

// Gets the string that corresponds to an error response byte.
// Since you can't scroll through the device's log, this should be printed on the host's end in case the user misses something.
const char* GetErrorString(char code)
{
	if ( code == ERR_NO_ARG[0] )
		return "No argument provided";
	if ( code == ERR_DIR_CLIMBING[0] )
		return "Directory traversal detected";
	if ( code == ERR_STAT[0] )
		return "stat(2) failed";
	if ( code == ERR_IOCTL[0] )
		return "ioctl(2) failed";
	if ( code == ERR_MKDIR[0] )
		return "mkdir(2) failed";
	if ( code == ERR_MOUNT[0] )
		return "mount(2) failed";
	if ( code == ERR_UMOUNT[0] )
		return "umount(2) failed";
	if ( code == ERR_RMDIR[0] )
		return "rmdir(2) failed";
	if ( code == ERR_FILE_TOO_BIG[0] )
		return "Directory traversal detected";
	if ( code == ERR_OPEN[0] )
		return "open(2) failed";
	if ( code == ERR_READ[0] )
		return "read(2) failed";
	if ( code == SUCCESS[0] )
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

// Receives a file's metadata from the device, and generates a digest of its contents as they are received.
// Returns 0 on success, -1 on failure, and 1 if a success response was received when file metadata was expected.
// WARNING: digest MUST be at least as long as the digest length or else a buffer overflow will happen!
int ReceiveFileMetaAndHash(int descFD, int epInID, struct file_metadata* fm, unsigned char* digest)
{
	char responseMetadata[1 + sizeof(struct file_metadata)];
	char responseFileBlock[1 + FILE_TRANSFER_BLOCK_SIZE];
	uint64_t fileSize;
	ssize_t bytesRead;
	size_t bytesToRead;
	size_t bytesLeftToRead;
	uint64_t bytesReadTotal = 0;
	uint64_t i;
	EVP_MD_CTX* ctx;

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

	memset(digest, '\0', HASHLEN);
	if ( S_ISREG(fm->mode) || S_ISBLK(fm->mode) )
	{
		// We need to receive the bytes from the device EXACTLY as they are sent, or else we could get a deadlock.
		// NOTE: Do NOT change the following without also changing it in the device code!
		//	 You risk desynchronization if you don't.
		fileSize = fm->fileSize;
		bytesLeftToRead = fileSize;
		ctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(ctx, HASHFUNC, NULL);
		for ( i = 0; i < fileSize; i += FILE_TRANSFER_BLOCK_SIZE )
		{
			bytesToRead = (bytesLeftToRead > FILE_TRANSFER_BLOCK_SIZE ? FILE_TRANSFER_BLOCK_SIZE : bytesLeftToRead);
			if ( bytesToRead == 0 )
				break;
			bytesRead = ReadFromDevice(descFD, epInID, responseFileBlock, 1 + bytesToRead);
			if ( bytesRead < 0 ) break;
			bytesLeftToRead -= bytesRead - 1;
			bytesReadTotal += bytesRead - 1;
			EVP_DigestUpdate(ctx, responseFileBlock + 1, bytesRead - 1);
		}
		EVP_DigestFinal_ex(ctx, digest, NULL);
		EVP_MD_CTX_free(ctx);
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
	if ( (S_ISREG(fm->mode) || S_ISBLK(fm->mode))
		&& bytesReadTotal != fileSize )	// Should never happen, but let's try to detect premature termination.
	{
		printf("!! Mismatch between stated file size (%lu) and bytes received (%lu) !!\n", fileSize, bytesReadTotal);
		return -1;
	}

	return 0;
}

// Requests a file from the device, gets its metadata, and if it's a regular file, generates a digest of its contents.
// Not to be confused with ReceiveFileMetaAndHash(), which only handles reception. Returns 0 on success, -1 on failure.
// WARNING: digest MUST be at least as long as the digest length or else a buffer overflow will happen!
int GetFileMetaAndHash(int descFD, int epInID, int epOutID, const char* reqPath, int followSymlinks, struct file_metadata* fm,
	unsigned char* digest)
{
	char cmd[1 + ARG_MAX_LEN];
	int reqPathLen;
	int ret;
	//int i;

	cmd[0] = (followSymlinks ? CMD_GET_FILE_FOLLOWSYMLINKS : CMD_GET_FILE);
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
	/*if ( ret == 0 )
	{
		printf("-- Received file %s having digest ", reqPath);
		for ( i = 0; i < HASHLEN; i++ ) printf("%02hhx", digest[i]);
		printf(" --\n");
	}*/
	return ret;
}

// Gets the metadata and hashes of all files under a directory, as deep as necessary.
// Also gets the directory under which all files are being checked.
// If saveFileFD is not -1, then this function also writes to the file pointed to by saveFileFD.
// Returns 0 on success, -1 on failure.
int GetAllFilesUnderDir(int descFD, int epInID, int epOutID, const char* reqPath, int saveFileFD)
{
	char cmd[1 + ARG_MAX_LEN];
	int reqPathLen;
	int ret;
	struct file_metadata fm;
	unsigned char digest[HASHLEN];

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

	while (1)
	{
		ret = ReceiveFileMetaAndHash(descFD, epInID, &fm, digest);
		if ( ret != 0 )
			break;
		if ( saveFileFD >= 0 )
		{
			if ( write(saveFileFD, &fm, sizeof(struct file_metadata)) < 0
				|| write(saveFileFD, digest, HASHLEN) < 0 )
			{
				printf("!! Error writing metadata for files under %s: %s !!\n", reqPath, strerror(errno));
				return -1;
			}
		}
	}
	return ret;
}


// ==== MAIN CODE ====

int main(int argc, char** argv)
{
	// == VARIABLES ==

	unsigned int i, j, k;

	int descFD, ifID, epInID, epOutID;

	char getPartsCmd[1];
	char curMetadataFile[NAME_MAX];
	int metadataFileFD;
	const void* metadataFileAddr;
	struct stat statbuf;
	int ret;
	unsigned int numRecords;
	char curFileRequest[ARG_MAX_LEN];
	struct file_metadata fm;
	const struct file_metadata* fm_trusted;
	unsigned char digest[HASHLEN];
	const unsigned char* digest_trusted;
	unsigned char digest_nonfs_trusted[HASHLEN];	// File with the known-good hash isn't memory-mapped.
	int bDataMismatch;
	int numMismatchedFiles;

	char filler;

	// == CODE ==

	// First step is to find the device with the vendor and product IDs of the verifier, then claim the USB interface.
	if ( InitUSBComms(&descFD, &ifID, &epInID, &epOutID) < 0 )
		return -1;

	// == FILE VERIFICATION ==

	// If no partitions have been specified, send the command to print them out.
	if ( NUM_PARTITIONS == 0 && NUM_NONFS_PARTITIONS == 0 )
	{
		printf("-- No partitions specified - see device screen for list --\n");
		getPartsCmd[0] = CMD_GET_PARTS;
		WriteToDevice(descFD, epOutID, getPartsCmd, 1);
	}

	printf("\n-- Checking metadata and hashes of files in block devices with EXT4/F2FS filesystems... --\n");
	for ( i = 0; i < NUM_PARTITIONS; i++ )
	{
		printf("\n==== %s ====\n", partitions_to_check[i]);

		snprintf(curMetadataFile, NAME_MAX, "./metadata_%s.dat", partitions_to_check[i]);
		ret = stat(curMetadataFile, &statbuf);
		if ( ret < 0 )
		{
			if ( errno == ENOENT )
			{
				printf("-- Trusted metadata file %s not present; creating and populating it... --\n", curMetadataFile);
				printf("-- WARNING: It is strongly recommended that you do this no later than after a fresh Android ");
				printf("installation --\n");

				metadataFileFD = open(curMetadataFile, O_WRONLY | O_CREAT, 0600);
				if ( metadataFileFD < 0 )
				{
					printf("!! Couldn't create file %s: %s !!\n", curMetadataFile, strerror(errno));
					continue;
				}

				// Get the metadata and hash of each file in this partition, after mounting it, from the device.
				if ( MountPartition(descFD, epInID, epOutID, partitions_to_check[i]) < 0 )
					continue;
				snprintf(curFileRequest, ARG_MAX_LEN, "%s/%s", MOUNTPOINT_PREFIX, partitions_to_check[i]);
				if ( GetAllFilesUnderDir(descFD, epInID, epOutID, curFileRequest, metadataFileFD) < 0 )
				{
					close(metadataFileFD);
					UnmountPartition(descFD, epInID, epOutID, partitions_to_check[i]);
					unlink(curMetadataFile);
					continue;
				}

				close(metadataFileFD);
				UnmountPartition(descFD, epInID, epOutID, partitions_to_check[i]);
			}
			else
			{
				printf("!! Skipping %s due to stat error: %s !!\n", curMetadataFile, strerror(errno));
			}

			continue;
		}

		// Get the number of records in the file. Fail if the file size isn't evenly divisible by the record size.
		if ( (size_t)statbuf.st_size % (sizeof(struct file_metadata) + HASHLEN) != 0 )
		{
			printf("!! Size of %s (%ld) not divisible by %lu !!\n", curMetadataFile, statbuf.st_size,
				sizeof(struct file_metadata) + HASHLEN);
			continue;
		}
		numRecords = (unsigned int)((size_t)statbuf.st_size / (sizeof(struct file_metadata) + HASHLEN));

		// File full of metadata exists; verify the device's contents.
		if ( MountPartition(descFD, epInID, epOutID, partitions_to_check[i]) < 0 )
			continue;
		printf("-- Verifying contents of %s... --\n", partitions_to_check[i]);

		metadataFileFD = open(curMetadataFile, O_RDONLY);
		if ( metadataFileFD < 0 )
		{
			printf("!! Couldn't open %s for reading: %s !!\n", curMetadataFile, strerror(errno));
			continue;
		}

		// File could be megabytes large, so let's memory-map it.
		metadataFileAddr = mmap(NULL, (size_t)statbuf.st_size, PROT_READ, MAP_PRIVATE, metadataFileFD, 0);
		if ( metadataFileAddr == MAP_FAILED )
		{
			printf("!! Unable to memory-map %s: %s !!\n", curMetadataFile, strerror(errno));
			close(metadataFileFD);
			continue;
		}

		numMismatchedFiles = 0;
		for ( j = 0; j < numRecords; j++ )
		{
			// Pointer arithmetic is scary, but I know what I'm doing here.
			fm_trusted = metadataFileAddr + j * (sizeof(struct file_metadata) + HASHLEN);
			digest_trusted = metadataFileAddr + j * (sizeof(struct file_metadata) + HASHLEN) +
						sizeof(struct file_metadata);

			strncpy(curFileRequest, fm_trusted->filepath, fm_trusted->filepathLen);
			memset(digest, '\0', HASHLEN);
			curFileRequest[fm_trusted->filepathLen] = '\0';
			if ( GetFileMetaAndHash(descFD, epInID, epOutID, curFileRequest, 0, &fm, digest) < 0 )
			{
				// Let's call it a mismatch. File could have been deleted, or God knows what else could have happened.
				printf("!! Failed to verify %s; considering it a mismatch and continuing on !!\n", curFileRequest);
				numMismatchedFiles++;
				continue;
			}

			// First compare file metadata.
			bDataMismatch = 0;
			if ( fm_trusted->uid != fm.uid )
			{
				printf("!! %s: UID MISMATCH (stored: %d, received: %d) !!\n", curFileRequest,
					fm_trusted->uid, fm.uid);
				bDataMismatch = 1;
			}
			if ( fm_trusted->gid != fm.gid )
			{
				printf("!! %s: GID MISMATCH (stored: %d, received: %d) !!\n", curFileRequest,
					fm_trusted->gid, fm.gid);
				bDataMismatch = 1;
			}
			if ( fm_trusted->mode != fm.mode )
			{
				printf("!! %s: MODE MISMATCH (stored: %o, received: %o) !!\n", curFileRequest,
					fm_trusted->mode, fm.mode);
				bDataMismatch = 1;
			}
			if ( S_ISDIR(fm.mode) && fm_trusted->fileSize != fm.fileSize )
			{
				// NOTE: Can't detect WHICH files in the directory are new/gone, only that at least one of them are.
				printf("!! %s: MISMATCH IN NUMBER OF DIRECTORY ENTITIES (stored: %zu, received: %zu) !!\n",
					curFileRequest, fm_trusted->fileSize, fm.fileSize);
				bDataMismatch = 1;
			}
			if ( fm_trusted->contextLen != fm.contextLen
				|| strncmp(fm_trusted->selinuxContext, fm.selinuxContext, fm_trusted->contextLen) != 0 )
			{
				printf("!! %s: SELINUX CONTEXT MISMATCH (stored: %s, received: %s) !!\n", curFileRequest,
					fm_trusted->selinuxContext, fm.selinuxContext);
				bDataMismatch = 1;
			}
			if ( fm_trusted->symlinkDestLen > 0
				&& strncmp(fm_trusted->symlinkDest, fm.symlinkDest, fm_trusted->symlinkDestLen) != 0 )
			{
				printf("!! %s: SYMLINK DESTINATION MISMATCH !!\n", curFileRequest);
				printf("!!\tstored: %s\t!!\n", fm_trusted->symlinkDest);
				printf("!!\treceived: %s\t!!\n", fm.symlinkDest);
				bDataMismatch = 1;
			}
			// Now, compare the file hashes.
			if ( memcmp(digest_trusted, digest, HASHLEN) != 0 )
			{
				printf("!! %s: CONTENTS CHANGED !!\n", curFileRequest);
				printf("!!\tstored hash: ");
				for ( k = 0; k < HASHLEN; k++ )
					printf("%02hhx", digest_trusted[k]);
				printf("\t!!\n");
				printf("!!\treceived hash: ");
				for ( k = 0; k < HASHLEN; k++ )
					printf("%02hhx", digest[k]);
				printf("\t!!\n");
				bDataMismatch = 1;
			}
			numMismatchedFiles += bDataMismatch;
		}
		printf("-- Finished verifying %s --\n", partitions_to_check[i]);
		printf("-- Number of mismatched files: %d --\n", numMismatchedFiles);

		UnmountPartition(descFD, epInID, epOutID, partitions_to_check[i]);
		munmap((char*)metadataFileAddr, (size_t)statbuf.st_size);
		close(metadataFileFD);
	}

	// == BLOCK DEVICE VERIFICATION ==

	printf("\n-- Checking hashes of partitions lacking EXT4/F2FS filesystems... --\n");
	for ( i = 0; i < NUM_NONFS_PARTITIONS; i++ )
	{
		printf("\n==== %s ====\n", nonfs_partitions_to_check[i]);

		snprintf(curMetadataFile, NAME_MAX, "hash_%s.dat", nonfs_partitions_to_check[i]);
		ret = stat(curMetadataFile, &statbuf);
		if ( ret < 0 )
		{
			if ( errno == ENOENT )
			{
				printf("-- Trusted metadata file %s not present; creating and populating it... --\n", curMetadataFile);
				printf("-- WARNING: It is strongly recommended that you do this no later than after a fresh Android ");
				printf("installation --\n");

				metadataFileFD = open(curMetadataFile, O_WRONLY | O_CREAT, 0600);
				if ( metadataFileFD < 0 )
				{
					printf("!! Couldn't create file %s: %s !!\n", curMetadataFile, strerror(errno));
					continue;
				}

				// Get the metadata and hash of the partition itself.
				snprintf(curFileRequest, ARG_MAX_LEN, "%s/%s", BLOCK_BY_NAME_PATH, nonfs_partitions_to_check[i]);
				if ( GetFileMetaAndHash(descFD, epInID, epOutID, curFileRequest, 1, &fm, digest) < 0 )
				{
					close(metadataFileFD);
					unlink(curMetadataFile);
					continue;
				}
				// Just write the hash. Devfs is a virtual file system, so file metadata doesn't really matter.
				if ( write(metadataFileFD, digest, HASHLEN) < 0 )
				{
					printf("!! Error writing to %s: %s !!\n", curMetadataFile, strerror(errno));
					close(metadataFileFD);
					unlink(curMetadataFile);
					continue;
				}

				close(metadataFileFD);
			}
			else
			{
				printf("!! Skipping %s due to stat error: %s !!\n", curMetadataFile, strerror(errno));
			}

			continue;
		}

		// Get the partition's hash and compare it.

		if ( (size_t)statbuf.st_size != HASHLEN )
		{
			printf("!! Size of %s not equal to the hash digest length !!\n", curMetadataFile);
			continue;
		}
		printf("-- Verifying hash of %s... --\n", nonfs_partitions_to_check[i]);

		metadataFileFD = open(curMetadataFile, O_RDONLY);
		if ( metadataFileFD < 0 )
		{
			printf("!! Couldn't open %s for reading: %s !!\n", curMetadataFile, strerror(errno));
			continue;
		}
		if ( read(metadataFileFD, digest_nonfs_trusted, HASHLEN) < 0 )
		{
			printf("!! Unable to get the known-good hash of partition %s: %s !!\n", curMetadataFile, strerror(errno));
			close(metadataFileFD);
			continue;
		}
		close(metadataFileFD);

		snprintf(curFileRequest, ARG_MAX_LEN, "%s/%s", BLOCK_BY_NAME_PATH, nonfs_partitions_to_check[i]);
		if ( GetFileMetaAndHash(descFD, epInID, epOutID, curFileRequest, 1, &fm, digest) < 0 )
		{
			close(metadataFileFD);
			continue;
		}

		if ( memcmp(digest_nonfs_trusted, digest, HASHLEN) != 0 )
		{
			printf("!! %s: CONTENTS CHANGED !!\n", curFileRequest);
			printf("!!\tstored hash: ");
			for ( k = 0; k < HASHLEN; k++ )
				printf("%02hhx", digest_nonfs_trusted[k]);
			printf("\t!!\n");
			printf("!!\treceived hash: ");
			for ( k = 0; k < HASHLEN; k++ )
				printf("%02hhx", digest[k]);
			printf("\t!!\n");
		}
		else
		{
			printf("-- Partition %s unmodified --\n", nonfs_partitions_to_check[i]);
		}

	}

	// == CLEANUP ==

	printf("\n");
	printf("-- Press ENTER to reboot device and exit --\n");
	scanf("%c", &filler);
	RebootDevice(descFD, epOutID);
	CloseUSBComms(descFD, ifID);
	return 0;
}
