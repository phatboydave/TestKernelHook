#include "memory.h"

bool write_memory(void* address, void* buffer, size_t size) {

	if (!RtlCopyMemory(address, buffer, size)) { // basically just memcpy
		return false;
	}

	return true;
}

bool write_read_only_memory(void* address, void* buffer, size_t size) {

	PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

	if (!Mdl) {
		return false;
	}

	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

	write_memory(Mapping, buffer, size);

	MmUnmapLockedPages(Mapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return true;
}

PVOID get_system_module_base(const char* module_name) {

	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);

	if (!bytes) {
		return NULL;
	}

	PRTL_PROCESS_MODULES module_list = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x70686174);

	status = ZwQuerySystemInformation(SystemModuleInformation, module_list, bytes, &bytes);

	if (!NT_SUCCESS(status)) {
		return NULL;
	}

	PRTL_PROCESS_MODULE_INFORMATION module = module_list->Modules;
	PVOID module_base = 0, module_size = 0;

	for (ULONG i = 0; i < module_list->NumberOfModules; i++) {

		if (strcmp((char*)module[i].FullPathName, module_name) == 0) {

			module_base = module[i].ImageBase;
			module_size = (PVOID)module[i].ImageSize;
			break;
		}
	}

	if (module_list) {
		ExFreePoolWithTag(module_list, NULL);
	}

	if (module_base <= 0) {
		return NULL;
	}

	return module_base;
}

PVOID get_system_module_export(const char* module_name, LPCSTR routine_name) {
	
	PVOID lpModule = get_system_module_base(module_name);

	if (!lpModule) {
		return NULL;
	}

	return RtlFindExportedRoutineByName(lpModule, routine_name);
}