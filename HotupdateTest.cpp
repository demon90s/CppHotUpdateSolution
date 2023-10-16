#include "HotupdateTest.h"
#include "Menu.h"
#include "Utility.h"

#include <sys/mman.h>
#include <dlfcn.h>
#include <unistd.h>
#include <link.h>

#include <stdlib.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <cassert>
#include <cstring>

static void TestUtility(void *p_test)
{
    Utility::Instance().consoleLog("Hello World");
}

static void CompileUtility(void *p_test)
{
    std::string compile_cmd = "g++ -g -Wall -std=c++11 -falign-functions=16 -o reload/Utility.o -fPIC -c Utility.cpp";
    int ret = system(compile_cmd.c_str());
    std::cout << (ret == 0 ? "[success] " : "[fail] ") << compile_cmd.c_str() << std::endl;
}

static void Reload(void *p_test)
{
    HotupdateTest *test = (HotupdateTest *)p_test;
    if (test->GetHotUpdateManager()->Reload())
    {
        printf("Reload success\n");
    }
}

static void ShowLoadedSharedObject(void *p_test)
{
    dl_iterate_phdr([](struct dl_phdr_info *info, size_t size, void *p_test) -> int {
		printf("- %s\t0x%lx\n", info->dlpi_name, info->dlpi_addr);
        return 0;
    }, NULL);
}

void HotupdateTest::Test()
{
    if (!m_hotupdate_manager.Init("reload", "g++ -g -Wall -std=c++11"))
    {
        return;
    }

    Menu menu("Hotupdate Test");

    menu.AddMenuItem(MenuItem("test Utility", TestUtility));
    menu.AddMenuItem(MenuItem("compile Utility", CompileUtility));
    menu.AddMenuItem(MenuItem("reload", Reload));
    menu.AddMenuItem(MenuItem("show loaded shared object", ShowLoadedSharedObject));
    menu.AddMenuItem(MenuItem("exit", [](void *) { exit(0); }));

    while (true)
    {
        //system("clear");
        menu.PrintMenu();
        menu.MakeChoice(this);
    }
}
