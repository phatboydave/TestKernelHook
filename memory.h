#pragma once
#include "definitions.h"

bool write_memory(void* address, void* buffer, size_t size);
bool write_read_only_memory(void* address, void* buffer, size_t size);

PVOID get_system_module_base(const char * module_name);
PVOID get_system_module_export(const char * module_name, LPCSTR routine_name);