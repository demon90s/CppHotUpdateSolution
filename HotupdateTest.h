#pragma once

#include "HotUpdateManager.hpp"

class HotupdateTest
{
public:
    void Test();

    HotUpdateManager *GetHotUpdateManager() { return &m_hotupdate_manager; }

private:
    HotUpdateManager m_hotupdate_manager;
};
