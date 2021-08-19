// COMP4905 - Honours Project, Carleton University
// Gabriel Valachi (101068875)

// This file contains the code needed for USB communications.
// Note that the USB interface is not found or claimed here; this needs to be done before any of the exported functions can be used.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>

#include <linux/usbdevice_fs.h>
#include <linux/usb/ch9.h>

#include "verifier_constants.h"
#include "usb_comms_host.h"
#ifdef SECURE_USB_COMMS
#include "privkey_verifier.h"
#include "pubkey_recovery.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#endif


// == PREPROCESSOR DEFS ==

#define USB_TRANSFER_LIMIT (16 * 1024)
#define TIMEOUT 0

// The vendor ID and product ID specified below MUST match the corresponding vendor/product IDs of the verifier, seen in
// recovery/etc/init.rc file of the Android recovery (under the sections where "on property:sys.usb.config=VERIFIER ..." is specified).
#define VERIFIER_VENDOR 0xE666
#define VERIFIER_PRODUCT 0xE666


// Reads at most numBytes from the device into inBuf.
// Returns the number of bytes read, or -1 if an error occurred (and also prints the error).
// NOTE: Declaration for ReadFromDevice_plain() not included in header file.
#ifdef SECURE_USB_COMMS
ssize_t ReadFromDevice_plain(int descFD, int epInID, void* inBuf, size_t numBytes)
#else
ssize_t ReadFromDevice(int descFD, int epInID, void* inBuf, size_t numBytes)
#endif
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
// NOTE: Declaration for WriteToDevice_plain() not included in header file.
#ifdef SECURE_USB_COMMS
ssize_t WriteToDevice_plain(int descFD, int epOutID, const void* outBuf, size_t numBytes)
#else
ssize_t WriteToDevice(int descFD, int epOutID, const void* outBuf, size_t numBytes)
#endif
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

#ifdef SECURE_USB_COMMS

// Encrypts and authenticates the plaintext using ChaCha20 and HMAC-SHA256, respectively, and following encrypt-then-MAC.
// encryptKey and macKey must both be 32 bytes (256 bits).
// On success (which is all the time unless the PC's out of memory), a pointer to the ciphertext and its length are set.
// The structure of the returned ciphertext is:
//	nonce (12 bytes)  +  ciphertext (plaintextLen bytes)  +  HMAC-SHA256 tag (32 bytes)
// ciphertext is dynamically allocated with malloc() (unless an error happens), so don't forget to free() it when you're done with it.
// NOTE: Declaration not included in header file.
int EncryptThenMAC(const unsigned char* plaintext, int plaintextLen, const unsigned char* encryptKey, const unsigned char* macKey,
			unsigned char** ciphertext, int* ciphertextLen)
{
	unsigned char iv[16];	// IV consists of initial block counter (= zero) in little-endian, followed by a random nonce.
	int randomFD;
	EVP_CIPHER_CTX* chachaCTX;
	int actualCiphertextLen;	// Just a filler variable. Ciphertext length must be equal to the plaintext length.
	int filler;

	// Read some random bytes in for the nonce, which by definition cannot be re-used.
	// Then, set the initial counter to zero.
	randomFD = open("/dev/random", O_RDONLY);
	read(randomFD, iv + 4, 12);
	close(randomFD);
	*(uint32_t*)(iv) = 0;

	// Create the encryption context and initialize it.
	chachaCTX = EVP_CIPHER_CTX_new();
	if ( chachaCTX == NULL )
		return -1;
	if ( EVP_EncryptInit_ex(chachaCTX, EVP_chacha20(), NULL, encryptKey, iv) != 1 )
	{
		EVP_CIPHER_CTX_free(chachaCTX);
		return -1;
	}
	EVP_CIPHER_CTX_set_padding(chachaCTX, 0);	// Disable padding. It's a stream cipher.

	// Allocate memory for the full ciphertext, then encrypt the data.
	*ciphertextLen = 12 + plaintextLen + 32;
	*ciphertext = malloc( *ciphertextLen );
	if ( *ciphertext == NULL )
	{
		EVP_CIPHER_CTX_free(chachaCTX);
		return -1;
	}
	memcpy(*ciphertext, iv + 4, 12);
	if ( EVP_EncryptUpdate(chachaCTX, *ciphertext + 12, &actualCiphertextLen, plaintext, plaintextLen) != 1 )
		goto error;

	// Just a matter of formalities; no more data should be written at all.
	if ( EVP_EncryptFinal_ex(chachaCTX, *ciphertext + actualCiphertextLen, &filler) != 1 )
		goto error;

	// Generate the MAC tag.
	if ( HMAC(EVP_sha256(), macKey, 32, *ciphertext, plaintextLen + 12, *ciphertext + (*ciphertextLen - 32), NULL) == NULL )
		goto error;

	EVP_CIPHER_CTX_free(chachaCTX);
	return 0;

	error:
	free(*ciphertext);
	EVP_CIPHER_CTX_free(chachaCTX);
	return -1;
}

// Authenticates and decrypts the ciphertext using HMAC-SHA256 and ChaCha20, respectively.
// encryptKey and macKey must both be 32 bytes (256 bits).
// If the nonce, ciphertext, or MAC tag are modifiedd, this operation fails. It should succeed otherwise, unless you're out of memory.
// plaintext is dynamically allocated with malloc() (unless an error happens), so don't forget to free() it when you're done with it.
// NOTE: Declaration not included in header file.
int MACThenDecrypt(const unsigned char* ciphertext, int ciphertextLen, const unsigned char* encryptKey, const unsigned char* macKey,
			unsigned char** plaintext, int* plaintextLen)
{
	unsigned char reconstructed_hmac[32];
	unsigned char iv[16];
	EVP_CIPHER_CTX* chachaCTX;
	int actualPlaintextLen;
	int filler;

	*plaintextLen = ciphertextLen - 12 - 32;

	// Check the HMAC.
	if ( HMAC(EVP_sha256(), macKey, 32, ciphertext, *plaintextLen + 12, reconstructed_hmac, NULL) == NULL )
		return -1;

	// HMAC check out. Set the IV.
	*(uint32_t*)(iv) = 0;
	memcpy(iv + 4, ciphertext, 12);

	chachaCTX = EVP_CIPHER_CTX_new();
	if ( chachaCTX == NULL )
		goto error;
	if ( EVP_DecryptInit_ex(chachaCTX, EVP_chacha20(), NULL, encryptKey, iv) != 1 )
		goto error;
	EVP_CIPHER_CTX_set_padding(chachaCTX, 0);	// Disable padding. It's a stream cipher.

	// Allocate memory for the plaintext, then decrypt the ciphertext.
	*plaintext = malloc( *plaintextLen );
	if ( *plaintext == NULL )
		goto error;
	if ( EVP_DecryptUpdate(chachaCTX, *plaintext, &actualPlaintextLen, ciphertext + 12, *plaintextLen) != 1 )
		goto error;

	// Just a matter of formalities; no more data should be written at all.
	if ( EVP_DecryptFinal_ex(chachaCTX, *plaintext + actualPlaintextLen, &filler) != 1 )
		goto error;

	EVP_CIPHER_CTX_free(chachaCTX);
	return 0;

	error:
	free(*plaintext);
	EVP_CIPHER_CTX_free(chachaCTX);
	return -1;
}

// Encryption and MAC keys. Must be 32 bytes long.
// Stored globally for backward compatibility with the ReadFromDevice()/WriteToDevice() functions.
unsigned char* g_encryptKey;
unsigned char* g_macKey;

// Derives two shared keys - one for encryption, one for MAC - using the Station-to-Station (StS) protocol.
// Elliptic-curve Diffie-Hellman using X25519 is used for the exchange itself, and Ed25519 is used for the signatures.
// The operation fails iff any of the data received fails to be verified.
int PerformECDHEKeyExchange(int descFD, int epInID, int epOutID)
{
        EVP_PKEY_CTX* keygenCTX;
        EVP_PKEY* pubkey = NULL;
        unsigned char pubkey_char[32];
        size_t pubkey_char_len;

	unsigned char recv_pubkey_encsig[32 + (12 + 64 + 32)];
        EVP_PKEY* devicekey;

        EVP_PKEY_CTX* deriveCTX;
        unsigned char* sharedSecret;
	size_t sharedSecretLen;

	EVP_PKEY_CTX* enckeyCTX;
	unsigned char encryptKey[32];
	size_t encryptKeyLen = 32;
	EVP_PKEY_CTX* mackeyCTX;
	unsigned char macKey[32];
	size_t macKeyLen = 32;

	unsigned char* recv_sig;
	int recv_sigLen;
	unsigned char concatenated[64];
	EVP_MD_CTX* verifyCTX;
	EVP_PKEY* pubEd25519DevKey;

	unsigned char concatenated2[64];
	EVP_PKEY* privEd25519Key;
	EVP_MD_CTX* signCTX;
	unsigned char sig[64];
	size_t sigLen = 64;
	unsigned char* sig_enc;
	int sig_encLen;

	// Generate the keypair.
	keygenCTX = EVP_PKEY_CTX_new_id(NID_X25519, NULL);
	EVP_PKEY_keygen_init(keygenCTX);
	EVP_PKEY_keygen(keygenCTX, &pubkey);
	EVP_PKEY_CTX_free(keygenCTX);

	// Send the verifier's public key, then receive the device's public key and an encrypted signature of (devkey || pubkey).
	EVP_PKEY_get_raw_public_key(pubkey, NULL, &pubkey_char_len);
	EVP_PKEY_get_raw_public_key(pubkey, pubkey_char, &pubkey_char_len);
	WriteToDevice_plain(descFD, epOutID, pubkey_char, 32);
	ReadFromDevice_plain(descFD, epInID, recv_pubkey_encsig, 32 + (12 + 64 + 32));

	devicekey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, recv_pubkey_encsig, 32);
	// Initialize the shared secret derivation context, set the peer's public key, then get the length of the shared secret.
	// Then actually derive the shared secret.
	deriveCTX = EVP_PKEY_CTX_new(pubkey, NULL);
	EVP_PKEY_derive_init(deriveCTX);
	EVP_PKEY_derive_set_peer(deriveCTX, devicekey);
	EVP_PKEY_derive(deriveCTX, NULL, &sharedSecretLen);
	sharedSecret = malloc(sharedSecretLen);
	EVP_PKEY_derive(deriveCTX, sharedSecret, &sharedSecretLen);
	EVP_PKEY_CTX_free(deriveCTX);

	// Derive the encryption key and MAC key, which cannot be equal since we're using encrypt-then-MAC.
	// Encryption key - HKDF on the shared secret.
	enckeyCTX = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	EVP_PKEY_derive_init(enckeyCTX);
	EVP_PKEY_CTX_set_hkdf_md(enckeyCTX, EVP_sha256());
	EVP_PKEY_CTX_set1_hkdf_key(enckeyCTX, sharedSecret, sharedSecretLen);
	EVP_PKEY_CTX_set1_hkdf_salt(enckeyCTX, HKDF_SALT, sizeof(HKDF_SALT));
	EVP_PKEY_CTX_add1_hkdf_info(enckeyCTX, HKDF_INFO, sizeof(HKDF_INFO));
	EVP_PKEY_derive(enckeyCTX, encryptKey, &encryptKeyLen);
	EVP_PKEY_CTX_free(enckeyCTX);
	// MAC key - HKDF on the encryption key.
	mackeyCTX = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	EVP_PKEY_derive_init(mackeyCTX);
	EVP_PKEY_CTX_set_hkdf_md(mackeyCTX, EVP_sha256());
	EVP_PKEY_CTX_set1_hkdf_key(mackeyCTX, encryptKey, encryptKeyLen);
	EVP_PKEY_CTX_set1_hkdf_salt(mackeyCTX, HKDF_SALT, sizeof(HKDF_SALT));
	EVP_PKEY_CTX_add1_hkdf_info(mackeyCTX, HKDF_INFO, sizeof(HKDF_INFO));
	EVP_PKEY_derive(mackeyCTX, macKey, &macKeyLen);
	EVP_PKEY_CTX_free(mackeyCTX);
	free(sharedSecret);	// No longer need the shared secret now that we derived it.

	// Decrypt the encrypted signature, concatenate (devkey || pubkey), and verify the signature.
	if ( MACThenDecrypt(recv_pubkey_encsig + 32, 12 + 64 + 32, encryptKey, macKey, &recv_sig, &recv_sigLen) < 0 )
	{
		EVP_PKEY_free(pubkey);
		EVP_PKEY_free(devicekey);
		return -1;
	}
	memcpy(concatenated, recv_pubkey_encsig, 32);
	memcpy(concatenated + 32, pubkey_char, 32);
	pubEd25519DevKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, RECOVERY_ED25519_PUBKEY, 32);
	verifyCTX = EVP_MD_CTX_new();
	EVP_DigestVerifyInit(verifyCTX, NULL, NULL, NULL, pubEd25519DevKey);
	if ( EVP_DigestVerify(verifyCTX, recv_sig, 64, concatenated, 64) != 1 )
	{
		EVP_PKEY_free(pubEd25519DevKey);
		EVP_MD_CTX_free(verifyCTX);
		EVP_PKEY_free(pubkey);
		EVP_PKEY_free(devicekey);
		free(recv_sig);
		return -1;
	}
	EVP_MD_CTX_free(verifyCTX);
	EVP_PKEY_free(pubEd25519DevKey);
	free(recv_sig);

	// Send the encrypted signature of the verifier's public key concatenated with the device's public key.
	memcpy(concatenated2, pubkey_char, 32);
	memcpy(concatenated2 + 32, recv_pubkey_encsig, 32);
	privEd25519Key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, VERIFIER_ED25519_PRIVKEY, 32);
	signCTX = EVP_MD_CTX_new();
	EVP_DigestSignInit(signCTX, NULL, NULL, NULL, privEd25519Key);
	EVP_DigestSign(signCTX, sig, &sigLen, concatenated2, 64);
	EVP_MD_CTX_free(signCTX);
	EVP_PKEY_free(privEd25519Key);
	EncryptThenMAC(sig, 64, encryptKey, macKey, &sig_enc, &sig_encLen);
	WriteToDevice_plain(descFD, epOutID, sig_enc, 12 + 64 + 32);
	free(sig_enc);

	g_encryptKey = malloc(32);
	g_macKey = malloc(32);
	memcpy(g_encryptKey, encryptKey, 32);
	memcpy(g_macKey, macKey, 32);

	EVP_PKEY_free(pubkey);
	EVP_PKEY_free(devicekey);
	return 0;
}

// Similar to ReadFromDevice_plain(), but authenticates and decrypts the data when it's received.
ssize_t ReadFromDevice(int descFD, int epInID, void* inBuf, size_t numBytes)
{
	unsigned char* ciphertext;
	int ciphertextLen;
	unsigned char* plaintext;
	int plaintextLen;

	ciphertext = malloc(12 + numBytes + 32);
	ciphertextLen = ReadFromDevice_plain(descFD, epInID, ciphertext, 12 + numBytes + 32);
	if ( ciphertextLen < 0 )
		return -1;
	if ( MACThenDecrypt(ciphertext, ciphertextLen, g_encryptKey, g_macKey, &plaintext, &plaintextLen) < 0 )
	{
		free(ciphertext);
		return -1;
	}

	free(ciphertext);
	memcpy(inBuf, plaintext, plaintextLen);
	free(plaintext);
	return plaintextLen;
}

// Similar to WriteToDevice_plain(), but encrypts and authenticates the data before it's sent.
ssize_t WriteToDevice(int descFD, int epOutID, const void* outBuf, size_t numBytes)
{
	unsigned char* plaintext;
	unsigned char* ciphertext;
	int ciphertextLen;
	int bytesWritten;

	plaintext = (unsigned char*)outBuf;
	if ( EncryptThenMAC(plaintext, numBytes, g_encryptKey, g_macKey, &ciphertext, &ciphertextLen) < 0 )
		return -1;
	bytesWritten = WriteToDevice_plain(descFD, epOutID, ciphertext, ciphertextLen);

	free(ciphertext);
	return bytesWritten;
}

// Frees the encryption and MAC keys.
void FreeKeys()
{
	free(g_encryptKey);
	free(g_macKey);
}

#endif	// SECURE_USB_COMMS

// Finds the recovery based on its vendor and product IDs.
// Return 0 on success, -1 on error.
// If successful, then the arguments descFD, ifID, epInID, and epOutID are given values of the control descriptor FD, interface ID,
// input endpoint ID, and output endpoint ID.
int InitUSBComms(int* descFD, int* ifID, int* epInID, int* epOutID)
{
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
			closedir(dirPtr);
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
	closedir(dirPtr);

	// Open the USB device for reading and writing, and get the descriptor.
	*descFD = open(devPath, O_RDWR);
	if ( descFD < 0 )
	{
		printf("!! Failed to open %s for reading/writing: %s !!\n", devPath, strerror(errno));
		printf("!! (NOTE: If it's a 'Permission denied' error, make sure the proper udev rules are in place; !!\n");
		printf("!! DO NOT TAKE THE EASY ROUTE AND RUN THIS PROGRAM AS ROOT) !!\n");
		return -1;
	}
	printf("-- Opened %s for reading/writing --\n", devPath);

	// We already know the USB interface ID, input endpoint ID, and output endpoint ID. They're defined in verifier_constants.h.
	// Knowing those, we can claim the USB interface.
	*ifID = INTERFACE_NUMBER;
	*epInID = IN_ADDR;
	*epOutID = OUT_ADDR;
	if ( ioctl(*descFD, USBDEVFS_CLAIMINTERFACE, ifID) < 0 )
	{
		printf("!! Unable to claim USB interface %d: %s !!\n", *ifID, strerror(errno));
		close(*descFD);
		return -1;
	}

#ifdef SECURE_USB_COMMS
	// Perform the ephemeral elliptic-curve Diffie-Hellman exchange.
	if ( PerformECDHEKeyExchange(*descFD, *epInID, *epOutID) < 0 )
	{
		printf("!! ECDHE key exchange failed - unplug the device to make it shut down --\n");
		close(*descFD);
		return -1;
	}
	else
		printf("-- ECDHE key exchange successful --\n");
#endif

	return 0;
}

void CloseUSBComms(int descFD, int ifID)
{
	if ( ioctl(descFD, USBDEVFS_RELEASEINTERFACE, &ifID) < 0 )	// If this fails, continue anyway, but report the error.
		printf("!! Unable to release USB interface %d: %s !!\n", ifID, strerror(errno));
#ifdef SECURE_USB_COMMS
	FreeKeys();
#endif
	close(descFD);
}
