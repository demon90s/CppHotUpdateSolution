#include "Menu.h"
#include <iostream>
#include <unistd.h>

Menu::Menu(const std::string &title) : m_title(title)
{
}

void Menu::AddMenuItem(const MenuItem &menu_item)
{
    m_menu_items.push_back(menu_item);
}

void Menu::PrintMenu()
{
    std::cout << "#" << getpid() << " " << m_title << std::endl;

    for (size_t index = 0; index < m_menu_items.size(); ++index)
    {
        std::cout << index + 1 << ") " << m_menu_items[index].GetContent() << std::endl;
    }

    std::cout << "your choice: ";
}

static void pauseInput()
{
    std::cout << "press enter to continue...";

    std::cin.get(); // 第一次把末尾的回车读了 否则 getline 会直接退出了
    std::string input;
    getline(std::cin, input);
}

void Menu::MakeChoice(void *data)
{
    std::string input;
    std::cin >> input;

    size_t index = -1;
    try
    {
        index = std::stoi(input);
        index -= 1;
    }
    catch (const std::exception &e)
    {
        std::cout << "wrong input, format error" << std::endl;
        pauseInput();
        return;
    }

    if (index >= m_menu_items.size())
    {
        std::cout << "no such choice" << std::endl;
        pauseInput();
        return;
    }

    m_menu_items[index].GetCallBack()(data);
    pauseInput();
}
