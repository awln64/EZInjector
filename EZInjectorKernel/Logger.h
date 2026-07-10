#pragma once
#include <ntifs.h>
#include <stdarg.h>
#include <ntstrsafe.h>

#ifndef NO_OUTPUT
#define NO_OUTPUT
#endif

void log_(const char* file, int line, const char* fmt, ...);
void error_(const char* file, int line, const char* fmt, ...);

#if defined(NO_OUTPUT) || defined(NDEBUG)
#define log(fmt, ...) ((void)0)
#define err(fmt, ...) ((void)0)
#else
#define log(fmt, ...) log_(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define err(fmt, ...) error_(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#endif