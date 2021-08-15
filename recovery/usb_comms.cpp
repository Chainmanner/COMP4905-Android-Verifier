// NOTE: Some source code taken from the relevant Fastboot device code (system/core/fastboot/device/usb_device.cpp) and from the Linux
//	 FunctionFS example (tools/usb/ffs-test.c).
// TODO: Add comments to this file.
// FIXME: There are still some unfinished parts. Complete them before finalizing the project.

#include <endian.h>
#include <fcntl.h>
#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <android-base/properties.h>

#include <openssl/evp.h>
#include <openssl/aead.h>
#include <openssl/chacha.h>
#include <openssl/curve25519.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "verifier_constants.h"

// FIXME: TEST CODE
#include "recovery_ui/device.h"
#include "recovery_ui/stub_ui.h"
#include "recovery_ui/ui.h"


// == PREPROCESSOR DEFS ==

#define FS_MAX_PACKET_SIZE 64
#define HS_MAX_PACKET_SIZE 512
#define SS_MAX_PACKET_SIZE 1024
#define NUM_BUFS 16
#define BUF_SIZE 16384

#define CONTROL_PATH "/dev/usb-ffs/VERIFIER/ep0"
#define OUT_PATH "/dev/usb-ffs/VERIFIER/ep1"
#define IN_PATH "/dev/usb-ffs/VERIFIER/ep2"

#define RECOVERY_ED25519_PRIVKEY "\xc9\x67\xcf\x1f\xab\x98\xdb\x78\x6d\x44\x4d\xfb\x1f\x72\x03\x75\xbe\xe9\x9c\xad\x2f\xac\x27\xf3\xd6\xe1\xac\x4f\xb4\x0e\x62\x8f"


// USB interface descriptor.
struct usb_interface_descriptor verifier_interface = {
	.bLength = USB_DT_INTERFACE_SIZE,
	.bDescriptorType = USB_DT_INTERFACE,
	.bInterfaceNumber = INTERFACE_NUMBER,
	.bNumEndpoints = 2,
	// Class, subclass, and protocol needed in order to identify the verifier USB interface on the host's end.
	// TODO: Do I need these? They're useful for finding the interface number and endpoint IDs, but the host already has them.
	.bInterfaceClass = INTERFACE_CLASS,
	.bInterfaceSubClass = INTERFACE_SUBCLASS,
	.bInterfaceProtocol = INTERFACE_PROTOCOL,
	.iInterface = 1,
};


// The descriptors that we'll need for USB comms.
static const struct {
	struct usb_functionfs_descs_head_v2 header;

	__le32 fs_count;
	__le32 hs_count;
	__le32 ss_count;

	struct {
		struct usb_interface_descriptor interface;
		struct usb_endpoint_descriptor_no_audio sink;
		struct usb_endpoint_descriptor_no_audio source;
	} __attribute__((packed)) fs_descs, hs_descs;
	struct {	// USB 3.0 has 5 descs.
		struct usb_interface_descriptor interface;
		struct usb_endpoint_descriptor_no_audio sink;
		struct usb_ss_ep_comp_descriptor sink_comp;
		struct usb_endpoint_descriptor_no_audio source;
		struct usb_ss_ep_comp_descriptor source_comp;
	} __attribute__((packed)) ss_descs;
} __attribute__((packed)) verifier_descriptors = {
	.header = {
		.magic = htole32(FUNCTIONFS_DESCRIPTORS_MAGIC_V2),
		.flags = htole32(FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC | FUNCTIONFS_HAS_SS_DESC),
		.length = htole32(sizeof(verifier_descriptors)),
	},

	.fs_count = htole32(3),
	.hs_count = htole32(3),
	.ss_count = htole32(5),

	.fs_descs = {
		.interface = verifier_interface,
		.sink = {
			.bLength = sizeof(verifier_descriptors.fs_descs.sink),
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = IN_ADDR,
			.bmAttributes = USB_ENDPOINT_XFER_BULK,
			.wMaxPacketSize = FS_MAX_PACKET_SIZE,
		},
		.source = {
			.bLength = sizeof(verifier_descriptors.fs_descs.source),
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = OUT_ADDR,
			.bmAttributes = USB_ENDPOINT_XFER_BULK,
			.wMaxPacketSize = FS_MAX_PACKET_SIZE,
		},
	},
	.hs_descs = {
		.interface = verifier_interface,
		.sink = {
			.bLength = sizeof(verifier_descriptors.hs_descs.sink),
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = IN_ADDR,
			.bmAttributes = USB_ENDPOINT_XFER_BULK,
			.wMaxPacketSize = HS_MAX_PACKET_SIZE,
		},
		.source = {
			.bLength = sizeof(verifier_descriptors.hs_descs.source),
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = OUT_ADDR,
			.bmAttributes = USB_ENDPOINT_XFER_BULK,
			.wMaxPacketSize = HS_MAX_PACKET_SIZE,
		},
	},
	.ss_descs = {
		.interface = verifier_interface,
		.sink = {
			.bLength = sizeof(verifier_descriptors.ss_descs.sink),
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = IN_ADDR,
			.bmAttributes = USB_ENDPOINT_XFER_BULK,
			.wMaxPacketSize = SS_MAX_PACKET_SIZE,
		},
		.sink_comp = {
			.bLength = sizeof(verifier_descriptors.ss_descs.sink_comp),
			.bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
			.bMaxBurst = 15,
		},
		.source = {
			.bLength = sizeof(verifier_descriptors.ss_descs.source),
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = OUT_ADDR,
			.bmAttributes = USB_ENDPOINT_XFER_BULK,
			.wMaxPacketSize = SS_MAX_PACKET_SIZE,
		},
		.source_comp = {
			.bLength = sizeof(verifier_descriptors.ss_descs.source_comp),
			.bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
			.bMaxBurst = 15,
		},
	},
};

// Strings for the verifier's USB comms.
#define INTERFACE_STR "VERIFIER"
static const struct {
	struct usb_functionfs_strings_head header;
	struct {
		__le16 code;
		const char str1[sizeof(INTERFACE_STR)];
	} __attribute__((packed)) lang0;
} __attribute__((packed)) verifier_strings = {
	.header = {
		.magic = htole32(FUNCTIONFS_STRINGS_MAGIC),
		.length = htole32(sizeof(verifier_strings)),
		.str_count = htole32(1),
		.lang_count = htole32(1),
	},
	.lang0 = {
		.code = htole16(0x409),
		.str1 = INTERFACE_STR,
	},
};


// File descriptors for the endpoints
int iControlFD;
int iOutFD;
int iInFD;


// == FUNCTIONS ==

// Opens the control endpoint, then writes the descriptors and strings to it.
// Then, opens the output and input endpoints.
// NOTE: Runs under the assumption that initialization has NOT been done before.
bool InitFunctionFS()
{
	int ret;
	iControlFD = open(CONTROL_PATH, O_RDWR);
	// TODO: Test if the control FD has been successfully opened.

	ret = write(iControlFD, &verifier_descriptors, sizeof(verifier_descriptors));
	// TODO: Test if the descriptors have been successfully written.
	ret = write(iControlFD, &verifier_strings, sizeof(verifier_strings));
	// TODO: Test if the strings have been successfully written.
	// Good to go.
	android::base::SetProperty("sys.usb.ffs.ready", "1");

	// Opens the output and input endpoints.
	iOutFD = open(OUT_PATH, O_WRONLY);
	// TODO: Test if the output FD has been successfully opened.
	iInFD = open(IN_PATH, O_RDONLY);
	// TODO: Test if the input FD has been successfully opened.

	return true;
}

// Closes the FunctionFS file descriptors.
void CloseFunctionFS()
{
	close(iControlFD);
	close(iOutFD);
	close(iInFD);
}

// Reads at most iNumBytes bytes from the host and store them in inBuf.
// Returns either the number of bytes read, or -1 if an error occurred.
// NOTE: If an error occurs, data may have still been read to inBuf.
ssize_t ReadFromHost(void* inBuf, size_t iNumBytes)
{
	char* inBuf_curPtr = (char*)inBuf;	// Must be char*; void* arithmetic not allowed.
	size_t bytesLeftToRead = iNumBytes;
	ssize_t bytesReadTotal = 0;
	ssize_t bytesRead;
	size_t bytesToRead;

	while ( bytesLeftToRead > 0 )
	{
		bytesToRead = bytesLeftToRead < NUM_BUFS * BUF_SIZE ? bytesLeftToRead : NUM_BUFS * BUF_SIZE;
		bytesRead = read(iInFD, inBuf_curPtr, bytesToRead);
		if ( bytesRead < 0 )	// Error occurred!
			return -1;
		bytesLeftToRead -= bytesRead;
		bytesReadTotal += bytesRead;
		inBuf_curPtr += bytesRead;
		if ( bytesRead < bytesToRead )	// Read less bytes than expected; end of transmission.
			break;
	}
	return bytesReadTotal;
	//return read(iInFD, inBuf, iNumBytes);
}

// Sends at most iNumBytes bytes from outBuf to the host.
// Returns either the number of bytes written, or -1 if an error occurred (with errno set appropriately).
// NOTE: If an error occurs, data from outBuf may have still been sent to the host.
ssize_t WriteToHost(const void* outBuf, size_t iNumBytes)
{
	char* outBuf_curPtr = (char*)outBuf;
	size_t bytesLeftToWrite = iNumBytes;
	ssize_t bytesWrittenTotal = 0;
	ssize_t bytesWritten;
	size_t bytesToWrite;

	while ( bytesLeftToWrite > 0 )
	{
		bytesToWrite = bytesLeftToWrite < NUM_BUFS * BUF_SIZE ? bytesLeftToWrite : NUM_BUFS * BUF_SIZE;
		bytesWritten = write(iOutFD, outBuf_curPtr, bytesToWrite);
		if ( bytesWritten < 0 )
			return -1;
		bytesLeftToWrite -= bytesWritten;
		bytesWrittenTotal += bytesWritten;
		outBuf_curPtr += bytesWritten;
		if ( bytesWritten < bytesToWrite )
			break;
	}
	return bytesWrittenTotal;
	//return write(iOutFD, outBuf, iNumBytes);
}

// Encrypts the plaintext using ChaCha20, then generates an HMAC-SHA256 tag for the ciphertext.
// NOTE: encryptKey and macKey must both be 32 bytes (256 bits).
// NOTE: ciphertext is dynamically allocated. Don't forget to free() it.
// FIXME: In the event of failure, I need to free up used resources.
bool EncryptThenMAC(const unsigned char* plaintext, int plaintextLen, const unsigned char* encryptKey, const unsigned char* macKey,
			unsigned char** ciphertext, int &ciphertextLen)
{
	unsigned char nonce[12];
	int randomFD;

	// Read some random bytes in for the nonce, which by definition cannot be re-used.
	randomFD = open("/dev/random", O_RDONLY);
	read(randomFD, nonce, 12);
	close(randomFD);

	// Allocate space for the ciphertext, then encrypt the plaintext using ChaCha20 and the encryption key.
	// Don't forget to also prefix the ciphertext with the nonce.
	ciphertextLen = 12 + plaintextLen + 32;
	*ciphertext = (unsigned char*)malloc( ciphertextLen );
	if ( *ciphertext == NULL )
		return false;
	memcpy(*ciphertext, nonce, 12);
	CRYPTO_chacha_20(*ciphertext + 12, plaintext, plaintextLen, encryptKey, nonce, 0);

	// Generate the MAC tag.
	if ( HMAC(EVP_sha256(), macKey, 32, *ciphertext + 12, plaintextLen, *ciphertext + (ciphertextLen - 32), NULL) == NULL )
		return false;

	return true;
}

// Checks the HMAC-SHA256 tag, then decrypts the ciphertext using ChaCha20.
// NOTE: encryptKey and macKey must both be 32 bytes (256 bits).
// NOTE: plaintext is dynamically allocated. Don't forget to free() it.
// FIXME: In the event of failure, I need to free up used resources.
bool MACThenDecrypt(const unsigned char* ciphertext, int ciphertextLen, const unsigned char* encryptKey, const unsigned char* macKey,
			unsigned char** plaintext, int &plaintextLen)
{
	unsigned char nonce[12];
	unsigned char reconstructed_hmac[32];
	// TODO: Should use pointers to the full ciphertext to reference certain parts (nonce, ciphertext itself, MAC tag).

	plaintextLen = ciphertextLen - 12 - 32;

	// Check the HMAC.
	if ( HMAC(EVP_sha256(), macKey, 32, ciphertext + 12, plaintextLen, reconstructed_hmac, NULL) == NULL )
		return false;
	if ( memcmp(reconstructed_hmac, ciphertext + (ciphertextLen - 32), 32) != 0 )
		return false;

	// HMAC checks out, so decrypt the ciphertext.
	*plaintext = (unsigned char*)malloc( plaintextLen );
	if ( *plaintext == NULL )
		return false;
	memcpy(nonce, ciphertext, 12);
	CRYPTO_chacha_20(*plaintext, ciphertext + 12, plaintextLen, encryptKey, nonce, 0);

	return true;
}

bool PerformECDHEKeyExchange(RecoveryUI* ui)	// FIXME: RecoveryUI is for testing.
{
	// FIXME: Station-to-Station protocol is NYI; this is only a test to see if ECDHE works.

	unsigned char pubkey[32];
	unsigned char privkey[32];
	unsigned char hostkey[32];
	unsigned char sharedkey[32];

	// BoringSSL provides an easy way to generate X25519 keypairs.
	X25519_keypair(pubkey, privkey);

	// Receive the verifier's public key, then send the recovery's.
	ReadFromHost(hostkey, 32);
	WriteToHost(pubkey, 32);
	// TODO: Concatenate the recovery's public key with the verifier's public key, sign the string, then send it encrypted along
	//	 with the public key.
	// TODO: Receive and verify the encrypted signature of the verifier's public key concatenated with the recovery's public key.

	X25519(sharedkey, privkey, hostkey);

	// FIXME: TEST CODE
	ui->Print("Shared secret: ");
	for ( int i = 0; i < 32; i++ )
		ui->Print("%02x", sharedkey[i]);
	ui->Print("\n");

	// FIXME: TEST CODE (obviously, as you can tell by the bad practices involving the shared secret)
	const unsigned char* plaintext = (unsigned char*)"wow such chacha20, very hmac-sha256";
	unsigned char* ciphertext = NULL;
	int ciphertextLen;
	unsigned char* plaintext_from_decryption = NULL;
	int plaintextLen;
	ui->Print("%d", EncryptThenMAC(plaintext, strlen((const char*)plaintext)+1, sharedkey, sharedkey, &ciphertext, ciphertextLen));
	ui->Print("%d\n", MACThenDecrypt(ciphertext, ciphertextLen, sharedkey, sharedkey, &plaintext_from_decryption, plaintextLen));
	ui->Print("%d %d\n", ciphertextLen, plaintextLen);
	ui->Print("Original plaintext:  %s\n", plaintext);
	ui->Print("Decrypted plaintext: %s\n", plaintext_from_decryption);
	WriteToHost(ciphertext, 12 + 36 + 32);
	unsigned char recv_ciphertext[12 + 45 + 32];
	unsigned char* recv_plaintext = NULL;
	int recv_plaintextLen;
	ReadFromHost(recv_ciphertext, 12 + 45 + 32);
	MACThenDecrypt(recv_ciphertext, 12 + 45 + 32, sharedkey, sharedkey, &recv_plaintext, recv_plaintextLen);
	ui->Print("received = %s\n", recv_plaintext);

	// TODO

	return true;
}
