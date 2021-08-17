// TODO: Add comments.

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
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>

#include "verifier_constants.h"
#include "pubkey_verifier.h"
#include "privkey_verifier.h"
#include "pubkey_recovery.h"


// ==== PREPROCESSOR DEFS ====

// The vendor ID and product ID specified below MUST match the corresponding vendor/product IDs of the verifier, seen in
// recovery/etc/init.rc file of the Android recovery (under the sections where "on property:sys.usb.config=VERIFIER ..." is specified).
#define VERIFIER_VENDOR 0xE666
#define VERIFIER_PRODUCT 0xE666

#define USB_TRANSFER_LIMIT (16 * 1024)
#define TIMEOUT 0

#define HASHFUNC EVP_blake2b512()	// The hash function to use.
#define HASHLEN 64			// The length of the hash function's digest in BYTES.

#define NUM_PARTITIONS 4
const char* partitions_to_check[] = {	// NOTE: Filesystems of the provided partitions MUST be EXT4 or F2FS.
	"system_a",
	"system_b",
	"vendor_a",
	"vendor_b",
};

#define NUM_NONFS_PARTITIONS 2
const char* nonfs_partitions_to_check[] = {	// These partitions don't have a valid filesystem, so we check them in their entirety.
	"boot_a",
	"boot_b",
};


// ==== FUNCTIONS ====

// Reads at most numBytes from the device into inBuf.
// Returns the number of bytes read, or -1 if an error occurred (and also prints the error).
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

#endif	// SECURE_USB_COMMS

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
	size_t fileSize;
	ssize_t bytesRead;
	size_t bytesToRead;
	size_t bytesLeftToRead;
	size_t bytesReadTotal = 0;
	size_t i;
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
		fileSize = (size_t)fm->fileSize;
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
	int ifID, epInID, epOutID;

	char getPartsCmd[1];
	char curMetadataFile[NAME_MAX];
	int metadataFileFD;
	const char* metadataFileAddr;
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
	descFD = open(devPath, O_RDWR);
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
	ifID = INTERFACE_NUMBER;
	epInID = IN_ADDR;
	epOutID = OUT_ADDR;
	if ( ioctl(descFD, USBDEVFS_CLAIMINTERFACE, &ifID) < 0 )
	{
		printf("!! Unable to claim USB interface %d: %s !!\n", ifID, strerror(errno));
		close(descFD);
		return -1;
	}

#ifdef SECURE_USB_COMMS
	// Perform the ephemeral elliptic-curve Diffie-Hellman exchange.
	if ( PerformECDHEKeyExchange(descFD, epInID, epOutID) < 0 )
	{
		printf("!! ECDHE key exchange failed - unplug the device to make it shut down --\n");
		close(descFD);
		return -1;
	}
	else
		printf("-- ECDHE key exchange successful --\n");
#endif

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
	if ( ioctl(descFD, USBDEVFS_RELEASEINTERFACE, &ifID) < 0 )	// If this fails, continue anyway, but report the error.
		printf("!! Unable to release USB interface %d: %s !!\n", ifID, strerror(errno));
#ifdef SECURE_USB_COMMS
	free(g_encryptKey);
	free(g_macKey);
#endif
	close(descFD);
	return 0;
}
