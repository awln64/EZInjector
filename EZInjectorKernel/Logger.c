#include "Logger.h"

void log_(const char* file, int line, const char* fmt, ...)
{
    char buffer[256] = { 0 };

    NTSTATUS status = RtlStringCbPrintfA(buffer, sizeof(buffer), "[+][Log %s:%d] ", file, line);
    if (NT_SUCCESS(status))
    {
        va_list args;
        va_start(args, fmt);
        vDbgPrintExWithPrefix(buffer, 0, 0, fmt, args);
        va_end(args);
    }
};

void error_(const char* file, int line, const char* fmt, ...)
{
    char buffer[256] = { 0 };

    NTSTATUS status = RtlStringCbPrintfA(buffer, sizeof(buffer), "[+][Error %s:%d] ", file, line);
    if (NT_SUCCESS(status))
    {
        va_list args;
        va_start(args, fmt);
        vDbgPrintExWithPrefix(buffer, 0, 0, fmt, args);
        va_end(args);
    }
};