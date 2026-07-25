#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#define NOINLINE __declspec(noinline)
#define MULTICHUNK_ENTRY __declspec(code_seg(".text$idaA"))
#define MULTICHUNK_GAP __declspec(code_seg(".text$idaM"))
#define MULTICHUNK_TAIL __declspec(code_seg(".text$idaZ"))
#else
#define EXPORT __attribute__((visibility("default")))
#define NOINLINE __attribute__((noinline))
#define MULTICHUNK_ENTRY __attribute__((section(".text.ida.a")))
#define MULTICHUNK_GAP __attribute__((section(".text.ida.m")))
#define MULTICHUNK_TAIL __attribute__((section(".text.ida.z")))
#endif
#define OPTNONE __attribute__((optnone))

typedef struct Record {
    uint32_t tag;
    int32_t score;
    const char *message;
} Record;

static const char accepted_text[] = "fixture: accepted";
static const char rejected_text[] = "fixture: rejected";
static volatile uint64_t observation_sink;
#if !defined(_WIN32)
static __thread uint32_t fixture_tls = 0xA5A55A5AU;
#endif

NOINLINE static int transform_add(int value) {
    return value + 17;
}

NOINLINE static int transform_xor(int value) {
    return value ^ 0x5A5A;
}

NOINLINE static int dispatch_switch(uint32_t selector, int value) {
    switch (selector & 7U) {
        case 0:
            return value + 3;
        case 1:
            return value - 5;
        case 2:
            return value * 7;
        case 3:
            return value ^ 0x1357;
        case 4:
            return value | 0x80;
        case 5:
            return value & 0x7FFF;
        case 6:
            return value << 2;
        default:
            return value >> 1;
    }
}

NOINLINE static int indirect_transform(int value, int choose_xor) {
    int (*transform)(int) = choose_xor ? transform_xor : transform_add;
    return transform(value);
}

EXPORT NOINLINE int fixture_validate(const Record *record, uint32_t selector) {
    int stage_one;
    int stage_two;

    if (record == NULL || record->message == NULL) {
        return -1;
    }
    stage_one = dispatch_switch(selector, record->score);
    stage_two = indirect_transform(stage_one, (record->tag & 1U) != 0U);
    observation_sink = (uint64_t)(uint32_t)stage_two;
    return record->message[0] == accepted_text[0] ? stage_two : -stage_two;
}

EXPORT NOINLINE const char *fixture_message(int accepted) {
    return accepted ? accepted_text : rejected_text;
}

EXPORT NOINLINE uint64_t fixture_observation(void) {
    return observation_sink;
}

EXPORT NOINLINE OPTNONE int fixture_dataflow_chain(int value) {
    int stage_one = value + 7;
    int stage_two = stage_one ^ 0x1234;
    return stage_two * 3;
}

MULTICHUNK_ENTRY EXPORT NOINLINE OPTNONE int fixture_multichunk_entry(int value) {
    observation_sink ^= (uint64_t)(uint32_t)value;
    return value + 0x31;
}

MULTICHUNK_GAP EXPORT NOINLINE OPTNONE int fixture_multichunk_gap(int value) {
    observation_sink += (uint64_t)(uint32_t)value;
    return value - 0x27;
}

MULTICHUNK_TAIL EXPORT NOINLINE OPTNONE int fixture_multichunk_tail(int value) {
    observation_sink |= (uint64_t)(uint32_t)value;
    return value ^ 0x5A17;
}

#if defined(_WIN32)
EXPORT NOINLINE int fixture_unwind_frame(int value) {
    volatile uint8_t scratch[96];
    scratch[0] = (uint8_t)value;
    scratch[95] = (uint8_t)(value >> 8);
    return indirect_transform((int)scratch[0] + (int)scratch[95], value & 1);
}

int __stdcall DllMain(void *module, unsigned long reason, void *reserved) {
    (void)module;
    (void)reason;
    (void)reserved;
    return 1;
}
#else
EXPORT NOINLINE uint32_t fixture_tls_step(uint32_t value) {
    fixture_tls ^= value;
    return fixture_tls;
}
#endif
