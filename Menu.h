#pragma once

#include "MenuItem.h"
#include <vector>

class Menu
{
public:
    Menu(const std::string &title);
    void AddMenuItem(const MenuItem &menu_item);
    void PrintMenu();
    void MakeChoice(void *data);

private:
    std::string m_title;
    std::vector<MenuItem> m_menu_items;
};
