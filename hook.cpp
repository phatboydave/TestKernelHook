#include "hook.h"

bool hook::call_kernel_function(void * kernel_function_address) {

	if (!kernel_function_address) {
		return false;
	}

	PVOID* function = reinterpret_cast<PVOID*>(get_system_module_export("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtQueryCompositionSurfaceStatistics")); // ADDRESS OF THE FUNCTION

	if (!function) {
		return false;
	}

	//BYTE total_shell_code[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // TO BE OVERRIDEN IN THE OVERRIDE SECITON
	BYTE total_shell_code[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	//BYTE orig_shell_code[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x4C, 0x89, 0x48, 0x20, 0x4C, 0x89, 0x40, 0x18, 0x48, 0x89, 0x48, 0x08 }; // OG BYTES (19 BYTES)

	//BYTE shell_code_start[] = { 0x48, 0xC7 }; // mov rbp, (ADDRESS ADDED LATER)
	//BYTE shell_code_end[] = { 0x48, 0x83, 0xFD, 0x00, 0xFF, 0xE5, 0x90, 0x90, 0x90 }; // cmp rbp, 0x0 (AND) 

	BYTE shell_code_start[] = { 0x48, 0xB8 }; // mov rax, xxx
	BYTE shell_code_end[] = { 0xFF, 0XE0 }; // jmp rax

	// OVERRIDE START
	RtlSecureZeroMemory(&total_shell_code, sizeof(total_shell_code));
	RtlCopyMemory((PVOID)((ULONG_PTR)total_shell_code), &shell_code_start, sizeof(shell_code_start));
	UINT_PTR hook_address = reinterpret_cast<UINT_PTR>(kernel_function_address);
	RtlCopyMemory((PVOID)((ULONG_PTR)total_shell_code + sizeof(shell_code_start)), &hook_address, sizeof(void*));
	RtlCopyMemory((PVOID)((ULONG_PTR)total_shell_code + sizeof(shell_code_start) + sizeof(void*)), &shell_code_end, sizeof(shell_code_end));
	// OVERRIDE END

	write_read_only_memory(function, &total_shell_code, sizeof(total_shell_code));

	return true;
}

NTSTATUS hook::hook_handler(PVOID called_param) {

	return STATUS_SUCCESS;
}