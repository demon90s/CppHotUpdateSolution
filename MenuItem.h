#pragma once

#include <string>

typedef void (*MenuItemCallback)(void *data);

class MenuItem
{
public:
    MenuItem();
    MenuItem(const std::string &content, MenuItemCallback callback);

    bool IsInvalid() const;

    const std::string &GetContent() const;
    MenuItemCallback GetCallBack() const;

private:
    std::string m_content;
    MenuItemCallback m_callback;
};
