package menubar

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa

#import <Cocoa/Cocoa.h>

// RegisterImageFromFile loads a PNG/JPEG file and registers it as an
// NSImage with the given name so that [NSImage imageNamed:] can find it.
// If isTemplate is nonzero, the image is marked as a template image
// (monochrome, auto-inverted by macOS for dark/light mode).
// Returns 1 on success, 0 on failure.
static int registerImageFromFile(const char *name, const char *path, int isTemplate) {
	NSString *nsPath = [NSString stringWithUTF8String:path];
	NSString *nsName = [NSString stringWithUTF8String:name];
	NSImage *image = [[NSImage alloc] initWithContentsOfFile:nsPath];
	if (image == nil) {
		return 0;
	}
	if (isTemplate) {
		[image setTemplate:YES];
	}
	[image setName:nsName];
	return 1;
}

// setApplicationIconFromFile loads an image and applies it as the NSApp icon
// used in Cmd+Tab and Dock when activation policy is regular.
// Returns 1 on success, 0 on failure.
static int setApplicationIconFromFile(const char *path) {
	NSString *nsPath = [NSString stringWithUTF8String:path];
	NSImage *image = [[NSImage alloc] initWithContentsOfFile:nsPath];
	if (image == nil) {
		return 0;
	}
	dispatch_async(dispatch_get_main_queue(), ^{
		[NSApp setApplicationIconImage:image];
	});
	return 1;
}
*/
import "C"
import (
	"strings"
	"unsafe"
)

// RegisterImage loads an image from a file path and registers it with
// NSImage under the given name. After registration, menuet can reference
// the image by this name in MenuState.Image or MenuItem.Image.
// The image is marked as a template image (monochrome, auto dark/light)
// if the filename contains "menubar-icon" or "Template".
func RegisterImage(name, filePath string) bool {
	cName := C.CString(name)
	cPath := C.CString(filePath)
	defer C.free(unsafe.Pointer(cName))
	defer C.free(unsafe.Pointer(cPath))
	isTemplate := C.int(0)
	if strings.Contains(filePath, "menubar-icon") || strings.Contains(filePath, "menu-") || strings.Contains(filePath, "Template") {
		isTemplate = 1
	}
	return C.registerImageFromFile(cName, cPath, isTemplate) == 1
}

// SetApplicationIcon sets the app icon used in Cmd+Tab/Dock while the app is
// visible as a regular macOS app (e.g. during Observation window display).
func SetApplicationIcon(filePath string) bool {
	cPath := C.CString(filePath)
	defer C.free(unsafe.Pointer(cPath))
	return C.setApplicationIconFromFile(cPath) == 1
}
