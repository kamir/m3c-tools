package menubar

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa

#import <Cocoa/Cocoa.h>

// RegisterImageFromFile loads a PNG/JPEG file and registers it as an
// NSImage with the given name so that [NSImage imageNamed:] can find it.
// Returns 1 on success, 0 on failure.
static int registerImageFromFile(const char *name, const char *path) {
	NSString *nsPath = [NSString stringWithUTF8String:path];
	NSString *nsName = [NSString stringWithUTF8String:name];
	NSImage *image = [[NSImage alloc] initWithContentsOfFile:nsPath];
	if (image == nil) {
		return 0;
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
import "unsafe"

// RegisterImage loads an image from a file path and registers it with
// NSImage under the given name. After registration, menuet can reference
// the image by this name in MenuState.Image or MenuItem.Image.
func RegisterImage(name, filePath string) bool {
	cName := C.CString(name)
	cPath := C.CString(filePath)
	defer C.free(unsafe.Pointer(cName))
	defer C.free(unsafe.Pointer(cPath))
	return C.registerImageFromFile(cName, cPath) == 1
}

// SetApplicationIcon sets the app icon used in Cmd+Tab/Dock while the app is
// visible as a regular macOS app (e.g. during Observation window display).
func SetApplicationIcon(filePath string) bool {
	cPath := C.CString(filePath)
	defer C.free(unsafe.Pointer(cPath))
	return C.setApplicationIconFromFile(cPath) == 1
}
