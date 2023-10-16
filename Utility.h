#pragma once

class Utility
{
public:
    static Utility &Instance();

    void consoleLog(const char *msg);
};