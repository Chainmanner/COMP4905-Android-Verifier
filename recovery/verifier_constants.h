#ifndef VERIFIER_CONSTANTS_H
#define VERIFIER_CONSTANTS_H

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
#define SECURE_USB_COMMS	// Comment this out to disable encryption and authentication for USB comms.
// NOTE: Keys generating using "openssl genpkey -text -algorithm ed25519". See the corresponding source files for the private keys.
// FIXME: I know configurations are hardcoded, but this doesn't seem like a great idea. Maybe keep the public/private keys in separate
//	  files? And have a script to regenerate keys?
#define VERIFIER_ED25519_PUBKEY "\x13\x08\xc5\x80\xc7\x84\xa9\x1f\x6c\x5d\x2b\x95\x1e\x34\x32\x41\xa4\x97\x39\x63\x24\xd7\x1a\xef\x19\x15\x39\x0b\x89\x6e\x50\x79"
#define RECOVERY_ED25519_PUBKEY "\x5a\xf8\x16\x1d\x67\x7d\x37\x91\x93\xd4\x48\xa3\x8b\x29\x02\x07\xec\xe8\x7b\x25\xaa\x52\xd8\x04\x08\x0c\xa0\x8a\xe0\x7e\x45\x70"

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
	size_t	filepathLen;
	char	filepath[ARG_MAX_LEN];
	uid_t	uid;
	gid_t	gid;
	mode_t	mode;
	size_t	contextLen;
	char	selinuxContext[SELINUX_CONTEXT_MAX_LEN];
	size_t	symlinkDestLen;
	char	symlinkDest[ARG_MAX_LEN];
	size_t	fileSize;
};


#endif	// VERIFIER_CONSTANTS_H
