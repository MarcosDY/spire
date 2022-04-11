//go:build windows
// +build windows

package process

import (
	"reflect"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modntdll    = windows.NewLazySystemDLL("ntdll.dll")

	procIsProcessInJob = modkernel32.NewProc("IsProcessInJob")

	procNtQuerySystemInformation = modntdll.NewProc("NtQuerySystemInformation")
	procNtQueryObject            = modntdll.NewProc("NtQueryObject")
)

const (
	// ObjectInformationClass values used to call NtQueryObject (https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject)
	ObjectNameInformationClass = 0x1
	ObjectTypeInformationClass = 0x2

	// Includes all processes in the system in the snapshot. (https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
	Th32csSnapProcess = 0x00000002
)

// System handle extended information item, returned by NtQuerySystemInformation (https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)
type SystemHandleInformationExItem struct {
	Object                uintptr
	UniqueProcessID       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
}

// System extended handle information summary, returned by NtQuerySystemInformation (https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)
type SystemExtendedHandleInformation struct {
	NumberOfHandles uintptr
	Reserved        uintptr
	Handles         [1]SystemHandleInformationExItem
}

// IsProcessInJob wraps library kernel32 function IsProcessInJob
func IsProcessInJob(procHandle windows.Handle, jobHandle windows.Handle, result *bool) error {
	r1, _, e1 := syscall.Syscall(procIsProcessInJob.Addr(), 3, uintptr(procHandle), uintptr(jobHandle), uintptr(unsafe.Pointer(result)))
	if r1 == 0 {
		if e1 != 0 {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

// NtQuerySystemInformation wraps library ntdll function NtQuerySystemInformation
func NtQuerySystemInformation(sysInfoClass int32, sysInfo unsafe.Pointer, sysInfoLen uint32, retLen *uint32) (ntstatus windows.NTStatus) {
	r0, _, _ := syscall.Syscall6(procNtQuerySystemInformation.Addr(), 4, uintptr(sysInfoClass), uintptr(sysInfo), uintptr(sysInfoLen), uintptr(unsafe.Pointer(retLen)), 0, 0)
	if r0 != 0 {
		ntstatus = windows.NTStatus(r0)
	}
	return
}

// NtQueryObject wraps library ntdll function NtQueryObject
func NtQueryObject(handle windows.Handle, objectInformationClass uint32, objectInformation *byte, objectInformationLength uint32, returnLength *uint32) error {
	r0, _, _ := syscall.Syscall6(procNtQueryObject.Addr(), 5, uintptr(handle), uintptr(objectInformationClass), uintptr(unsafe.Pointer(objectInformation)), uintptr(objectInformationLength), uintptr(unsafe.Pointer(returnLength)), 0)
	if r0 != 0 {
		return windows.NTStatus(r0)
	}
	return nil
}

func NtQueryObject2(handle windows.Handle, objectInformationClass uint32, objectInformation *byte, objectInformationLength uint32, returnLength *uint32) (status uint32, err error) {
	r0, _, e1 := syscall.Syscall6(procNtQueryObject.Addr(), 5, uintptr(handle), uintptr(objectInformationClass), uintptr(unsafe.Pointer(objectInformation)), uintptr(objectInformationLength), uintptr(unsafe.Pointer(returnLength)), 0)
	status = uint32(r0)
	if status == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return status, err
}

func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

// Object type returned by calling NtQueryObject function
type ObjectTypeInformation struct {
	TypeName               UnicodeString
	TotalNumberOfObjects   uint32
	TotalNumberOfHandles   uint32
	TotalPagedPoolUsage    uint32
	TotalNonPagedPoolUsage uint32
}

// Unicode string returned by NtQueryObject calls (https://docs.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string)
type UnicodeString struct {
	Length        uint16
	AllocatedSize uint16
	WString       *byte
}

func (u UnicodeString) String() string {
	defer func() {
		// TODO: may we recover?
		_ = recover()
	}()

	var data []uint16

	sh := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	sh.Data = uintptr(unsafe.Pointer(u.WString))
	sh.Len = int(u.Length * 2)
	sh.Cap = int(u.Length * 2)

	return windows.UTF16ToString(data)
}
