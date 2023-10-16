#include "MenuItem.h"

MenuItem::MenuItem() : m_callback(nullptr)
{
}

MenuItem::MenuItem(const std::string &content, MenuItemCallback callback) : m_content(content), m_callback(callback)
{
}

bool MenuItem::IsInvalid() const
{
    return m_content.empty() || m_callback == nullptr;
}

const std::string &MenuItem::GetContent() const
{
    return m_content;
}

MenuItemCallback MenuItem::GetCallBack() const
{
    return m_callback;
}
