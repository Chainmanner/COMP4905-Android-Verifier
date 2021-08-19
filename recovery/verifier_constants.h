// COMP4905 - Honours Project, Carleton University
// Gabriel Valachi (101068875)

#ifndef VERIFIER_CONSTANTS_H
#define VERIFIER_CONSTANTS_H

#include <stdint.h>

// Definitions that must be consistent on the device AND host code.

#define MAX_FILE_SIZE 536870900l	// About 512 MiB. I don't think there will be any files larger than that, but we'll see.
#define ARG_MAX_LEN 512			// Max length for command arguments (which are usually paths). Includes the null terminator.
#define BLOCK_BY_NAME_PATH "/dev/block/by-name"	// Dir with block devices by name. Don't know if it's consistent for all devices.
#define MOUNTPOINT_PREFIX "/mnt"	// Directory in which to mount block devices.
#define SELINUX_CONTEXT_MAX_LEN 64	// Max length of an SELinux context. Hopefully this is large enough to avoid truncation...
#define FILE_TRANSFER_BLOCK_SIZE 4096l	// Number of bytes of the file being verified to send at a time.

// USB Comms
#define INTERFACE_NUMBER 0
#define INTERFACE_CLASS 0xd7
#define INTERFACE_SUBCLASS 0x9f
#define INTERFACE_PROTOCOL 6
#define IN_ADDR (1 | USB_DIR_IN)	// NOTE: "In" from the host's perspective.
#define OUT_ADDR (1 | USB_DIR_OUT)	// NOTE: "Out" from the host's perspective.

// Comms Security
// Uncomment this preprocessor def to enable authenticated encryption for USB comms.
// This will protect against the highly unlikely case of a malicious USB cable, but the verification will take ~3.5 times longer.
//#define SECURE_USB_COMMS
// These two are needed for HKDF.
#define HKDF_SALT (unsigned char*)"the saltiest of the salts"			// Used for the "extract" part of HKDF.
#define HKDF_INFO (unsigned char*)"does this need to be random or something"	// Used for the "expand" part of HKDF.

// Commands
#define CMD_GET_PARTS			0x9d
#define CMD_MNT_DEV			0xbd
#define CMD_UMNT_DEV			0x0d
#define CMD_GET_FILE_FOLLOWSYMLINKS	0x95
#define CMD_GET_FILE			0x9f
#define CMD_GET_ALL			0xaf
#define CMD_SHUTDOWN			0x5d

// Responses
#define SUCCESS			"\x55"
#define FILE_METADATA		"\xfd"
#define FILE_CONTENT		"\xfc"
#define ERR_NO_ARG		"\x0a"
#define ERR_DIR_CLIMBING	"\xdc"
#define ERR_STAT		"\x57"
#define ERR_IOCTL		"\x10"
#define ERR_MKDIR		"\xdd"
#define ERR_MOUNT		"\xb0"
#define ERR_UMOUNT		"\x0b"
#define ERR_RMDIR		"\xd0"
#define ERR_FILE_TOO_BIG	"\x2b"
#define ERR_OPEN		"\xf0"
#define ERR_READ		"\xfe"

// Apparently the stat struct may differ across architectures, so to be safe, here's a definition with only the necessary types.
struct file_metadata {
	size_t		filepathLen;
	char		filepath[ARG_MAX_LEN];
	uid_t		uid;
	gid_t		gid;
	mode_t		mode;
	size_t		contextLen;
	char		selinuxContext[SELINUX_CONTEXT_MAX_LEN];
	size_t		symlinkDestLen;
	char		symlinkDest[ARG_MAX_LEN];
	uint64_t	fileSize;	// Needs to be 64 bits long due to the use of the BLKGETSIZE64 ioctl call.
};


#endif	// VERIFIER_CONSTANTS_H
