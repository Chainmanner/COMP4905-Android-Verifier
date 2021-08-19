// COMP4905 - Honours Project, Carleton University
// Gabriel Valachi (101068875)

// Header file for usb_comms_host.c. Contains all the function definitions needed to communicate with an Android device over USB.

#ifndef USB_COMMS_HOST_H
#define USB_COMMS_HOST_H

#include "verifier_constants.h"

// This function find the recovery based on its vendor and product IDs, then claims the interface and returns the interface ID, input
// endpoint ID, and output endpoint ID.
// Returns 0 on success, -1 on error.
int InitUSBComms(int* descFD, int* ifID, int* epInID, int* epOutID);
// Shuts down USB comms by closing the descriptor FD and freeing the encryption/MAC keys (if applicable).
void CloseUSBComms(int descFD, int ifID);

// NOTE: The above two functions are found near the end of usb_comms_host.c.

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

// NOTE: Functions only available when SECURE_USB_COMMS is defined are not exported, as they're not needed outside of usb_comms_host.c.

#endif	// USB_COMMS_HOST_H
