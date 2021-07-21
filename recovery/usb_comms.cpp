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


// == DEFINITIONS ==


// Preprocessor defs
#define FS_MAX_PACKET_SIZE 64
#define HS_MAX_PACKET_SIZE 512
#define SS_MAX_PACKET_SIZE 1024
#define NUM_BUFS 16
#define BUF_SIZE 16384

#define CONTROL_PATH "/dev/usb-ffs/VERIFIER/ep0"
#define OUT_PATH "/dev/usb-ffs/VERIFIER/ep1"
#define IN_PATH "/dev/usb-ffs/VERIFIER/ep2"


// USB interface descriptor.
// TODO: Is this right? I need to make sure this is right.
struct usb_interface_descriptor verifier_interface = {
	.bLength = USB_DT_INTERFACE_SIZE,
	.bDescriptorType = USB_DT_INTERFACE,
	.bInterfaceNumber = 0,
	.bNumEndpoints = 2,
	// Class, subclass, and protocol needed in order to identify the verifier USB interface on the host's end.
	.bInterfaceClass = 0xd7,
	.bInterfaceSubClass = 0x9f,
	.bInterfaceProtocol = 6,
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
			.bEndpointAddress = 1 | USB_DIR_IN,
			.bmAttributes = USB_ENDPOINT_XFER_BULK,
			.wMaxPacketSize = FS_MAX_PACKET_SIZE,
		},
		.source = {
			.bLength = sizeof(verifier_descriptors.fs_descs.source),
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = 1 | USB_DIR_OUT,
			.bmAttributes = USB_ENDPOINT_XFER_BULK,
			.wMaxPacketSize = FS_MAX_PACKET_SIZE,
		},
	},
	.hs_descs = {
		.interface = verifier_interface,
		.sink = {
			.bLength = sizeof(verifier_descriptors.hs_descs.sink),
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = 1 | USB_DIR_IN,
			.bmAttributes = USB_ENDPOINT_XFER_BULK,
			.wMaxPacketSize = HS_MAX_PACKET_SIZE,
		},
		.source = {
			.bLength = sizeof(verifier_descriptors.hs_descs.source),
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = 1 | USB_DIR_OUT,
			.bmAttributes = USB_ENDPOINT_XFER_BULK,
			.wMaxPacketSize = HS_MAX_PACKET_SIZE,
		},
	},
	.ss_descs = {
		.interface = verifier_interface,
		.sink = {
			.bLength = sizeof(verifier_descriptors.ss_descs.sink),
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = 1 | USB_DIR_IN,
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
			.bEndpointAddress = 1 | USB_DIR_OUT,
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

// Wrapper for read(2).
// Returns either the number of bytes read, or -1 if an error occurred (with errno set appropriately).
int ReadFromHost(void* inBuf, size_t iNumBytes)
{
	return read(iInFD, inBuf, iNumBytes);
}

// Wrapper for write(2).
// Returns either the number of bytes written, or -1 if an error occurred (with errno set appropriately).
int WriteToHost(const void* outBuf, size_t iNumBytes)
{
	return write(iOutFD, outBuf, iNumBytes);
}
