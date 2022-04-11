//go:build windows
// +build windows

package process

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// GetContainerIDByProcess get container ID from provided process ID,
// on windows process that are running in a docker containers are grouped by Named Jobs,
// those Jobs has the container ID as name.
// In the format `\Container_${CONTAINER_ID}`
func GetContainerIDByProcess(pID int32) (string, error) {
	// Search all processes that runs vmcompute.exe
	vmComputeProcessIds, err := searchProcessByExeFile("vmcompute.exe")
	if err != nil {
		return "", fmt.Errorf("failed to search vmcompute process: %w", err)
	}

	// Get current process
	currentProcess := windows.CurrentProcess()
	defer func() {
		_ = windows.CloseHandle(currentProcess)
	}()

	// Duplicate process handle we want to validate, with limited permissions
	childProcessHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pID))
	if err != nil {
		return "", fmt.Errorf("failed to open child process: %w", err)
	}
	defer func() {
		_ = windows.CloseHandle(childProcessHandle)
	}()

	buffer, err := querySystemInformation()
	if err != nil {
		return "", fmt.Errorf("failed to query system information: %w", err)
	}

	handlesList := (*SystemExtendedHandleInformation)(unsafe.Pointer(&buffer[0]))
	handles := make([]SystemHandleInformationExItem, int(handlesList.NumberOfHandles))
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&handles))
	hdr.Data = uintptr(unsafe.Pointer(&handlesList.Handles[0]))

	// Verify if process ID is a vmcompute process
	isVmcomputeProcess := func(pID uint32) bool {
		for _, vmID := range vmComputeProcessIds {
			if pID == vmID {
				return true
			}
		}
		return false
	}

	var jobNames []string
	for _, handle := range handles {
		// Filter all handles related with vmcompute processes
		if !isVmcomputeProcess(uint32(handle.UniqueProcessID)) {
			continue
		}

		// Open handle process ID, with permissions to duplicateg handle
		hProcess, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, uint32(handle.UniqueProcessID))
		if err != nil {
			// TODO: may I just continue?
			// return "", fmt.Errorf("failed to open process: %v", err)
			continue
		}
		defer func() {
			_ = windows.CloseHandle(hProcess)
		}()

		// Duplicate handle to get information
		var dupHandle windows.Handle
		if windows.DuplicateHandle(hProcess, windows.Handle(handle.HandleValue), currentProcess, &dupHandle,
			0, true, windows.DUPLICATE_SAME_ACCESS) != nil {
			continue
		}
		defer func() {
			_ = windows.CloseHandle(dupHandle)
		}()

		typeName, err := getObjectType(dupHandle)
		if err != nil {
			return "", err
		}

		// Filter no Jobs handlers
		if typeName != "Job" {
			continue
		}

		isProcessInJob := false
		if err := IsProcessInJob(childProcessHandle, dupHandle, &isProcessInJob); err != nil {
			return "", err
		}

		if !isProcessInJob {
			continue
		}

		objectName, err := getObjectName(dupHandle)
		if err != nil {
			return "", err
		}

		// Jobs created on windows environments start with "\Container_"
		if !strings.HasPrefix(objectName, `\Container_`) {
			continue
		}

		jobNames = append(jobNames, objectName)
	}

	if len(jobNames) > 1 {
		return "", fmt.Errorf("process has multiple jobs: %v", jobNames)
	}

	return jobNames[0][11:], nil
}

// querySystemInformation use NtQuerySystemInformation to get all handles runnig on system
func querySystemInformation() ([]byte, error) {
	buffer := make([]byte, 1024)
	var retLen uint32
	var status windows.NTStatus

	for {
		status = NtQuerySystemInformation(
			windows.SystemExtendedHandleInformation,
			unsafe.Pointer(&buffer[0]),
			uint32(len(buffer)),
			&retLen,
		)

		if status == windows.STATUS_BUFFER_OVERFLOW ||
			status == windows.STATUS_BUFFER_TOO_SMALL ||
			status == windows.STATUS_INFO_LENGTH_MISMATCH {
			if int(retLen) <= cap(buffer) {
				(*reflect.SliceHeader)(unsafe.Pointer(&buffer)).Len = int(retLen)
			} else {
				buffer = make([]byte, int(retLen))
			}
			continue
		}
		// if no error
		if status>>30 != 3 {
			buffer = (buffer)[:int(retLen)]
			return buffer, nil
		}
		return nil, status
	}
}

// searchProcessByExeFile search all process with specified exe file
func searchProcessByExeFile(exeFile string) ([]uint32, error) {
	snapshotHandle, err := windows.CreateToolhelp32Snapshot(Th32csSnapProcess, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = windows.CloseHandle(snapshotHandle)
	}()

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshotHandle, &entry); err != nil {
		return nil, err
	}

	var results []uint32

	for {
		entryExeFile := syscall.UTF16ToString(entry.ExeFile[:])
		if entryExeFile == exeFile {
			results = append(results, entry.ProcessID)
		}

		if err := windows.Process32Next(snapshotHandle, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return nil, err
		}
	}

	return results, nil
}

// getObjectType get the handle type
func getObjectType(handle windows.Handle) (string, error) {
	buffer := make([]byte, 1024*10)
	length := uint32(0)

	status := NtQueryObject(handle, ObjectTypeInformationClass,
		&buffer[0], uint32(len(buffer)), &length)
	if status != nil && status != windows.STATUS_SUCCESS {
		return "", status
	}

	return (*ObjectTypeInformation)(unsafe.Pointer(&buffer[0])).TypeName.String(), nil
}

// getObjectName get the handle name
func getObjectName(handle windows.Handle) (string, error) {
	buffer := make([]byte, 1024*2)
	var length uint32

	status := NtQueryObject(handle, ObjectNameInformationClass,
		&buffer[0], uint32(len(buffer)), &length)
	if status != nil && status != windows.STATUS_SUCCESS {
		return "", status
	}

	return (*UnicodeString)(unsafe.Pointer(&buffer[0])).String(), nil
}
