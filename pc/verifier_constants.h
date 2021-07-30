#ifndef VERIFIER_CONSTANTS_H
#define VERIFIER_CONSTANTS_H

// Definitions that must be consistent on the device AND host code.

#define MAX_FILE_SIZE 536870900l	// About 512 MiB. I don't think there will be any files larger than that, but we'll see.
#define ARG_MAX_LEN 512	// Including the null terminator.
#define SELINUX_CONTEXT_MAX_LEN 64

// Commands
#define CMD_GET_FILE 0x9f
#define CMD_SHUTDOWN 0x5d

// Responses
#define SUCCESS			"\x55"
#define ERR_NO_FILE		"\x0f"
#define ERR_DIR_CLIMBING	"\xdc"
#define ERR_STAT		"\x57"
//#define ERR_IRREGULAR_FILE	"\x1f"
#define ERR_FILE_TOO_BIG	"\x2b"
#define ERR_OPEN		"\xf0"
#define ERR_READ		"\xfe"
#define ERR_READ_SIZE_MISMATCH	"\xf5"

// Apparently the stat struct may differ across architectures, so to be safe, here's a definition with only the necessary types.
struct file_metadata {
	uid_t	uid;
	gid_t	gid;
	mode_t	mode;
	size_t contextLen;
	char selinuxContext[SELINUX_CONTEXT_MAX_LEN];
	off_t	fileSize;
};


#endif	// VERIFIER_CONSTANTS_H
