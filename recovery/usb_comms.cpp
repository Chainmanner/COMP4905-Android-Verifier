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

// This file contains the code needed for the recovery to communicate with the verifier over USB.
// This includes setting up the USB connection. In order to do that, the FunctionFS endpoint at /dev/usb-ffs/VERIFIER/ep0 must be
// created. After InitUSBComms() is called, the vendor and product IDs of the USB interface must be set, and the USB interface must be
// activated.
// These additional steps are handled by the etc/init.rc file, which is run when the recovery ramdisk is loaded.

// NOTE: Some source code taken from the relevant Fastboot device code (system/core/fastboot/device/usb_device.cpp in Android source
// code) and from the Linux FunctionFS example (tools/usb/ffs-test.c in the Linux kernel source).

#include <endian.h>
#include <fcntl.h>
#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <android-base/properties.h>

#include <openssl/evp.h>
#include <openssl/chacha.h>
#include <openssl/curve25519.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "verifier_constants.h"
#ifdef SECURE_USB_COMMS
#include "pubkey_verifier.h"
#include "pubkey_recovery.h"
#include "privkey_recovery.h"
#endif


// == PREPROCESSOR DEFS ==

#define FS_MAX_PACKET_SIZE 64
#define HS_MAX_PACKET_SIZE 512
#define SS_MAX_PACKET_SIZE 1024
#define NUM_BUFS 16
#define BUF_SIZE 16384

#define CONTROL_PATH "/dev/usb-ffs/VERIFIER/ep0"
#define OUT_PATH "/dev/usb-ffs/VERIFIER/ep1"
#define IN_PATH "/dev/usb-ffs/VERIFIER/ep2"


// USB interface descriptor.
struct usb_interface_descriptor verifier_interface = {
	.bLength = USB_DT_INTERFACE_SIZE,
	.bDescriptorType = USB_DT_INTERFACE,
	.bInterfaceNumber = INTERFACE_NUMBER,
	.bNumEndpoints = 2,
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

#ifdef SECURE_USB_COMMS
// Encryption and MAC keys.
unsigned char* g_encryptKey;
unsigned char* g_macKey;
#endif


// == FUNCTIONS ==

// Reads at most iNumBytes bytes from the host and store them in inBuf.
// Returns either the number of bytes read, or -1 if an error occurred.
// NOTE: If an error occurs, data may have still been read to inBuf.
#ifdef SECURE_USB_COMMS
ssize_t ReadFromHost_plain(void* inBuf, size_t iNumBytes)
#else
ssize_t ReadFromHost(void* inBuf, size_t iNumBytes)
#endif
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
#ifdef SECURE_USB_COMMS
ssize_t WriteToHost_plain(const void* outBuf, size_t iNumBytes)
#else
ssize_t WriteToHost(const void* outBuf, size_t iNumBytes)
#endif
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

#ifdef SECURE_USB_COMMS

// Encrypts the plaintext using ChaCha20, then generates an HMAC-SHA256 tag for the ciphertext.
// NOTE: encryptKey and macKey must both be 32 bytes (256 bits).
// NOTE: ciphertext is dynamically allocated. Don't forget to free() it.
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
	if ( HMAC(EVP_sha256(), macKey, 32, *ciphertext, plaintextLen + 12, *ciphertext + (ciphertextLen - 32), NULL) == NULL )
	{
		free(*ciphertext);
		return false;
	}

	return true;
}

// Checks the HMAC-SHA256 tag, then decrypts the ciphertext using ChaCha20.
// NOTE: encryptKey and macKey must both be 32 bytes (256 bits).
// NOTE: plaintext is dynamically allocated. Don't forget to free() it.
bool MACThenDecrypt(const unsigned char* ciphertext, int ciphertextLen, const unsigned char* encryptKey, const unsigned char* macKey,
			unsigned char** plaintext, int &plaintextLen)
{
	unsigned char nonce[12];
	unsigned char reconstructed_hmac[32];

	plaintextLen = ciphertextLen - 12 - 32;

	// Check the HMAC.
	if ( HMAC(EVP_sha256(), macKey, 32, ciphertext, plaintextLen + 12, reconstructed_hmac, NULL) == NULL )
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

// Derives two shared keys - one for encryption, one for MAC - using the Station-to-Station (StS) protocol.
// Elliptic-curve Diffie-Hellman using X25519 is used for the exchange itself, and Ed25519 is used for the signatures.
// The operation fails iff any of the data received fails to be verified.
bool PerformECDHEKeyExchange()
{
	unsigned char pubkey[32];
	unsigned char privkey[32];
	unsigned char hostkey[32];
	unsigned char sharedsecret[32];

	unsigned char encryptkey[32];
	unsigned char mackey[32];

	unsigned char concatenated[64];
	unsigned char bothkeys[64];	// BoringSSL has Ed25519 private keys be suffixed with the corresponding public keys.
	unsigned char concatenated_sig[64];
	unsigned char* concatenated_sig_enc;
	int concatenated_sig_enc_len;
	unsigned char pubkey_encsig[32 + (12 + 64 + 32)];	// pubkey + concatenated_sig_enc

	unsigned char recv_encsig[12 + 64 + 32];
	unsigned char* recv_sig;
	int recv_sig_len;
	unsigned char concatenated2[64];

	// BoringSSL provides an easy way to generate X25519 keypairs.
	X25519_keypair(pubkey, privkey);

	// Receive the verifier's public key, then derive the shared secret.
	if ( ReadFromHost_plain(hostkey, 32) < 0 )
		return false;;
	X25519(sharedsecret, privkey, hostkey);

	// Derive two keys from the shared secret, one for encryption and the other for the MAC.
	// Since we're using encrypt-then-MAC, we should not use the same key for both the encryption and the MAC.
	// For the encryption key, use HKDF on the shared secret. For the MAC key, use HKDF on the encryption key.
	HKDF(encryptkey, 32, EVP_sha256(), sharedsecret, 32, HKDF_SALT, sizeof(HKDF_SALT), HKDF_INFO, sizeof(HKDF_INFO));
	HKDF(mackey, 32, EVP_sha256(), encryptkey, 32, HKDF_SALT, sizeof(HKDF_SALT), HKDF_INFO, sizeof(HKDF_INFO));

	// Concatenate our public ECDHE key with that of the verifier.
	memcpy(concatenated, pubkey, 32);
	memcpy(concatenated + 32, hostkey, 32);
	// Sign the concatenation.
	memcpy(bothkeys, RECOVERY_ED25519_PRIVKEY, 32);
	memcpy(bothkeys + 32, RECOVERY_ED25519_PUBKEY, 32);
	ED25519_sign(concatenated_sig, concatenated, 64, bothkeys);
	// Encrypt the signature (with authentication included).
	EncryptThenMAC(concatenated_sig, 64, encryptkey, mackey, &concatenated_sig_enc, concatenated_sig_enc_len);
	// Send the ECDHE public key and the encrypted + authenticated signature of (pubkey || hostkey) to the verifier.
	memcpy(pubkey_encsig, pubkey, 32);
	memcpy(pubkey_encsig + 32, concatenated_sig_enc, 12 + 64 + 32);
	free(concatenated_sig_enc);
	if ( WriteToHost_plain(pubkey_encsig, 32 + (12 + 64 + 32)) < 0 )
		return false;

	// Receive the encrypted signature of (hostkey || pubkey), decrypt it, then verify it.
	if ( ReadFromHost_plain(recv_encsig, 12 + 64 + 32) < 0 )
		return false;
	MACThenDecrypt(recv_encsig, 12 + 64 + 32, encryptkey, mackey, &recv_sig, recv_sig_len);
	memcpy(concatenated2, hostkey, 32);
	memcpy(concatenated2 + 32, pubkey, 32);
	if ( ED25519_verify(concatenated2, 64, recv_sig, VERIFIER_ED25519_PUBKEY) != 1 )
	{
		free(recv_sig);
		return false;
	}
	free(recv_sig);

	// Export the generated keys.
	g_encryptKey = (unsigned char*)malloc(32);
	g_macKey = (unsigned char*)malloc(32);
	memcpy(g_encryptKey, encryptkey, 32);
	memcpy(g_macKey, mackey, 32);

	return true;
}

// Encrypted and authenticated variant of ReadFromHost_plain().
ssize_t ReadFromHost(void* inBuf, size_t iNumBytes)
{
	unsigned char* ciphertext;
	int ciphertextLen;
	unsigned char* plaintext;
	int plaintextLen;

	ciphertext = (unsigned char*)malloc(12 + iNumBytes + 32);
	ciphertextLen = ReadFromHost_plain(ciphertext, 12 + iNumBytes + 32);
	if ( ciphertextLen < 0 )
		return ciphertextLen;
	if ( !MACThenDecrypt(ciphertext, ciphertextLen, g_encryptKey, g_macKey, &plaintext, plaintextLen) )
	{
		free(ciphertext);
		return -1;
	}

	free(ciphertext);
	memcpy(inBuf, plaintext, plaintextLen);
	free(plaintext);
	return plaintextLen;
}

// Encrypted and authenticated variant of WriteToHost_plain().
ssize_t WriteToHost(const void* outBuf, size_t iNumBytes)
{
	unsigned char* plaintext;
	unsigned char* ciphertext;
	int ciphertextLen;
	int bytesWritten;

	plaintext = (unsigned char*)outBuf;
	if ( !EncryptThenMAC(plaintext, iNumBytes, g_encryptKey, g_macKey, &ciphertext, ciphertextLen) )
		return -1;
	bytesWritten = WriteToHost_plain(ciphertext, ciphertextLen);

	free(ciphertext);
	return bytesWritten;
}

#endif	// SECURE_USB_COMMS

// Opens the control endpoint, then writes the descriptors and strings to it.
// Then, opens the output and input endpoints and activates the USB interface.
// If authenticated encryption is enabled, also performs the key exchange with the verifier.
// NOTE: Runs under the assumption that initialization has NOT been done before.
bool InitUSBComms()
{
	int ret;
	iControlFD = open(CONTROL_PATH, O_RDWR);
	if ( iControlFD < 0 )
		return false;

	ret = write(iControlFD, &verifier_descriptors, sizeof(verifier_descriptors));
	if ( ret < 0 )
		return false;
	ret = write(iControlFD, &verifier_strings, sizeof(verifier_strings));
	if ( ret < 0 )
		return false;
	// Good to go.
	android::base::SetProperty("sys.usb.ffs.ready", "1");

	// Opens the output and input endpoints.
	iOutFD = open(OUT_PATH, O_WRONLY);
	if ( iOutFD < 0 )
		return false;
	iInFD = open(IN_PATH, O_RDONLY);
	if ( iInFD < 0 )
		return false;
	
	// Verifier's ready to communicate.
	android::base::SetProperty("sys.usb.config", "VERIFIER");
	android::base::WaitForProperty("sys.usb.state", "VERIFIER");

#ifdef SECURE_USB_COMMS
	return PerformECDHEKeyExchange();	// Last part is to perform the key exchange.
#else
	return true;
#endif
}

// Closes the file descriptors, and frees encryption and MAC keys if applicable.
void CloseUSBComms()
{
	close(iControlFD);
	close(iOutFD);
	close(iInFD);
#ifdef SECURE_USB_COMMS
	free(g_encryptKey);
	free(g_macKey);
#endif
}
