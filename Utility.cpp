#include "Utility.h"
#include <iostream>
#include <vector>

Utility & Utility::Instance()
{
    static Utility inst;
    return inst; 
}

class Foo
{
public:
    Foo() { printf("0x%lx Foo()\n", size_t(this)); }
    ~Foo() { printf("0x%lx ~Foo()\n", (size_t)this); }

    std::vector<std::string> v = { "hello world" };
};
// Foo g_foo;

extern void somefunc_in_other_cpp();

void testStatic()
{
    static Foo foo;
    (void)foo;
}

void Utility::consoleLog(const char *msg)
{
    somefunc_in_other_cpp();
    printf("%s\n", msg);

    // char date[1024];
    // time_t now = time(NULL);
    // strftime(date, 1024, "%Y-%m-%d %H:%M:%S", localtime(&now));
    // printf("[%s] %s\n", date, msg);

    // static int call_times = 0;
    // call_times++;
    // printf("[%d 0x%lx] %s\n", call_times, (unsigned long)&call_times, msg);
}
