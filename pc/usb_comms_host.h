// COMP4905 - Honours Project, Carleton University
// Gabriel Valachi (101068875)

// Header file for usb_comms_host.c. Contains all the function definitions needed to communicate with an Android device over USB.

#ifndef USB_COMMS_HOST_H
#define USB_COMMS_HOST_H

#include "verifier_constants.h"

// The below two functions read and write data from/to the connected Android device, after the recovery has finished setting itself up.
// Note that in order to use these functions, the device's USB interface must be found and claimed.
//	descFD is the file descriptor for the USB device file under /dev/bus/usb/...
//	epInID is the ID of the input endpoint, used to receive data from the device.
//	epOutID is the ID of the output endpoint, used to transmit data to the device.
//	numBytes is the number of bytes to read or write.
// The number of bytes actually received/sent is returned on success, and -1 is returned on failure with an error message also being
// printed out.
// If authenticated encryption is enabled, these functions will encrypt/decrypt and authenticate the data being sent/received.

// inBuf is the buffer to store received data.
ssize_t ReadFromDevice(int descFD, int epInID, void* inBuf, size_t numBytes);
// outBuf is the buffer containing the data to be sent.
ssize_t WriteToDevice(int descFD, int epOutID, const void* outBuf, size_t numBytes);

// NOTE: Functions ReadFromDevice_plain(), WriteToDevice_plain(), EncryptThenMAC(), and MACThenDecrypt() are not exported, as they
// are not needed outside usb_comms_host.c.
#ifdef SECURE_USB_COMMS
// If authenticate encryption for USB communications is enabled, the below function will perform an ephemeral elliptic-curve
// Diffie-Hellman key exchange with the recovery to generate a shared secret, then derive an encryption key and a separate MAC key.
// These keys are stored as globals within usb_comms_host.c.
int PerformECDHEKeyExchange(int descFD, int epInID, int epOutID);
// When the verifier is done, remember to free the encryption and MAC keys!
void FreeKeys();
#endif

#endif	// USB_COMMS_HOST_H
