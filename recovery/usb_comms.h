// COMP4905 - Honours Project, Carleton University
// Gabriel Valachi (101068875)

// Header file for usb_comms.cpp. Contains all the function definitions needed to communicate with the verifier over USB.

#ifndef USB_COMMS_H
#define USB_COMMS_H

#include "verifier_constants.h"

// Creates the I/O endpoints and enables USB communications.
bool InitUSBComms();
// Closes the I/O file descriptors, and frees the encryption and MAC keys.
void CloseUSBComms();

// The below two functions read and write data from/to the connected verifier, after setup is done.
// numBytes is the number of bytes to read or write.

// inBuf is the buffer to store received data.
ssize_t ReadFromHost(void* inBuf, size_t iNumBytes);
// outBuf is the buffer containing the data to be sent.
ssize_t WriteToHost(const void* outBuf, size_t iNumBytes);

// NOTE: Functions only available when SECURE_USB_COMMS is defined are not exported, as they're not needed outside of usb_comms.cpp.

#endif	// USB_COMMS_H
