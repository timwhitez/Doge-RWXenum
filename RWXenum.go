package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uint64
	AllocationBase    uint64
	AllocationProtect uint32
	Allignment        uint32
	RegionSize        uint64
	State             uint32
	Protect           uint32
	Type              uint32
	Allignment2       uint32
}


func main(){
	nt := syscall.NewLazyDLL("ntdll.dll")
	NtQueryVirtualMemory := nt.NewProc("NtQueryVirtualMemory")
	var offset uintptr
	var mbi MEMORY_BASIC_INFORMATION

	snapshot,_ := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	processEntry := syscall.ProcessEntry32{}
	processEntry.Size = uint32(unsafe.Sizeof(syscall.ProcessEntry32{}))

	syscall.Process32First(snapshot, &processEntry)

	for syscall.Process32Next(snapshot, &processEntry) == nil {
		process, _ := syscall.OpenProcess(0x02000000, false, processEntry.ProcessID)
		if process != 0 {
			var retLength uintptr
			for r,_,_ := NtQueryVirtualmem(NtQueryVirtualMemory,uintptr(process),offset,uintptr(unsafe.Pointer(&mbi)),unsafe.Sizeof(mbi),&retLength); r == 0; r,_,_ = NtQueryVirtualmem(NtQueryVirtualMemory,uintptr(process),offset,uintptr(unsafe.Pointer(&mbi)),unsafe.Sizeof(mbi),&retLength){
				offset = uintptr(mbi.BaseAddress + mbi.RegionSize)
				if ((mbi.AllocationProtect == syscall.PAGE_EXECUTE_READWRITE || mbi.AllocationProtect == syscall.PAGE_EXECUTE_READ || mbi.AllocationProtect == syscall.PAGE_EXECUTE_WRITECOPY) && mbi.State == windows.MEM_COMMIT && mbi.Type == 0x20000) {
					fmt.Println(syscall.UTF16ToString(processEntry.ExeFile[:]))
					fmt.Printf("BaseAddress: 0x%x\n", mbi.BaseAddress)
					fmt.Printf("Size: %x\n", mbi.RegionSize)
				}
			}
			offset = 0
		}
	}
}


func NtQueryVirtualmem(NtQueryVirtualMemory *syscall.LazyProc,phndl uintptr, offset uintptr, mbi uintptr, size uintptr, rlenth *uintptr)(uintptr,uintptr,error){
	type MEMORY_INFORMATION_CLASS int
	const (
		MemoryBasicInformation MEMORY_INFORMATION_CLASS = iota
	)
	r1,r2,lastErr := NtQueryVirtualMemory.Call(
		phndl,
		offset,
		uintptr(MemoryBasicInformation),
		mbi,
		size,
		uintptr(unsafe.Pointer(rlenth)),
	)
	return r1,r2,lastErr
}

