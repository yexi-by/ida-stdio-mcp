#include <stdint.h>

#define EXPORT __declspec(dllexport)
#define NOINLINE __declspec(noinline)
#define WINAPI __stdcall

typedef void *HANDLE;
typedef unsigned long DWORD;
typedef void *LPVOID;
typedef DWORD(WINAPI *ThreadRoutine)(LPVOID);

__declspec(dllimport) HANDLE WINAPI CreateThread(
    LPVOID attributes,
    uintptr_t stack_size,
    ThreadRoutine start_routine,
    LPVOID parameter,
    DWORD creation_flags,
    DWORD *thread_id
);
__declspec(dllimport) DWORD WINAPI WaitForSingleObject(HANDLE handle, DWORD milliseconds);
__declspec(dllimport) const uint16_t *WINAPI GetCommandLineW(void);
__declspec(dllimport) uint64_t WINAPI GetTickCount64(void);
__declspec(dllimport) void WINAPI ExitProcess(unsigned int exit_code);

static volatile uint64_t debug_marker = 0x1122334455667788ULL;
static const char debug_text[] = "fixture: debugger reached checkpoint";
EXPORT const void *debug_relocation_anchor = (const void *)&debug_marker;

EXPORT NOINLINE int debug_leaf(int value) {
    volatile int stack_value = value + 9;
    debug_marker ^= (uint64_t)(uint32_t)stack_value;
    return stack_value * 3;
}

EXPORT NOINLINE int debug_mid(int value) {
    return debug_leaf(value) + 11;
}

static DWORD WINAPI debug_thread(LPVOID parameter) {
    int value = (int)(uintptr_t)parameter;
    debug_marker += (uint64_t)(uint32_t)debug_mid(value);
    return (DWORD)value;
}

EXPORT NOINLINE uint64_t debug_read_marker(void) {
    return debug_marker + (uint64_t)(unsigned char)debug_text[0];
}

static int should_hold_for_debugger(void) {
    static const uint16_t hold_argument[] = {
        '-', '-', 'i', 'd', 'a', '-', 'r', 'e', '-', 'h', 'o', 'l', 'd', 0
    };
    const uint16_t *command_line = GetCommandLineW();
    if (command_line == (const uint16_t *)0) {
        return 0;
    }
    for (uintptr_t offset = 0; command_line[offset] != 0; ++offset) {
        uintptr_t index = 0;
        while (
            hold_argument[index] != 0
            && command_line[offset + index] == hold_argument[index]
        ) {
            ++index;
        }
        if (hold_argument[index] == 0) {
            return 1;
        }
    }
    return 0;
}

void mainCRTStartup(void) {
    DWORD thread_id = 0;
    HANDLE thread = CreateThread(
        (LPVOID)0,
        0,
        debug_thread,
        (LPVOID)(uintptr_t)7,
        0,
        &thread_id
    );
    int result = debug_mid(5);
    if (thread != (HANDLE)0) {
        (void)WaitForSingleObject(thread, 5000);
    }
    if (should_hold_for_debugger()) {
        uint64_t deadline = GetTickCount64() + 60000;
        while (GetTickCount64() < deadline) {
            debug_marker ^= 0;
        }
    }
    ExitProcess((unsigned int)(result & 0xFF));
}
