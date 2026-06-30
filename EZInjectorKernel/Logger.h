#include <ntifs.h>
#include <stdarg.h>
#include <ntstrsafe.h>

void log_(const char* file, int line, const char* fmt, ...);
void error_(const char* file, int line, const char* fmt, ...);

#ifdef NO_OUTPUT
#define log(fmt, ...)
#define err(fmt, ...)
#else
#define log(fmt, ...) log_(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define err(fmt, ...) error_(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#endif