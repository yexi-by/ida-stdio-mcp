#include <stdint.h>

#if defined(_WIN32)
#define EXPORT extern "C" __declspec(dllexport)
#define NOINLINE __declspec(noinline)
#else
#define EXPORT extern "C" __attribute__((visibility("default")))
#define NOINLINE __attribute__((noinline))
#endif

struct ObjectHeader {
    void *klass;
    void *monitor;
};

struct Vec3 {
    float x;
    float y;
    float z;
};

struct Actor {
    ObjectHeader object;
    int32_t instance_id;
    Vec3 position;
};

enum class ActorState : int32_t {
    Idle = 0,
    Running = 1,
    Disabled = 2,
};

struct ActorStatics {
    int32_t live_count;
    Actor *last_actor;
};

struct MethodMetadata {
    const char *name;
    uint32_t token;
};

EXPORT ActorStatics il2cpp_actor_statics = {0, nullptr};

EXPORT NOINLINE int32_t Actor_GetScore(Actor *self, int32_t bonus, const MethodMetadata *method) {
    if (self == nullptr || method == nullptr) {
        return -1;
    }
    return self->instance_id + bonus + (int32_t)(method->token & 0xFFU);
}

EXPORT NOINLINE int32_t Actor_GetScore_Overload(
    Actor *self,
    int32_t bonus,
    int32_t multiplier,
    const MethodMetadata *method
) {
    return Actor_GetScore(self, bonus, method) * multiplier;
}

EXPORT NOINLINE int32_t Generic_SharedBody(void *value, const MethodMetadata *method) {
    return value != nullptr && method != nullptr ? (int32_t)(method->token & 0x7FFFU) : 0;
}

EXPORT NOINLINE int32_t Actor_AdjustorThunk(Actor *self, const MethodMetadata *method) {
    return Actor_GetScore(self, 0, method);
}

EXPORT NOINLINE int32_t Actor_Invoker(
    int32_t (*target)(Actor *, int32_t, const MethodMetadata *),
    Actor *self,
    const MethodMetadata *method
) {
    return target(self, 4, method);
}

#if defined(_WIN32)
int __stdcall DllMain(void *module, unsigned long reason, void *reserved) {
    (void)module;
    (void)reason;
    (void)reserved;
    return 1;
}
#endif
