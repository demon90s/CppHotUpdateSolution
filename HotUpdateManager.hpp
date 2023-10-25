#pragma once

#include <map>
#include <string>
#include <vector>
#include <set>

class HotUpdateManager
{
public:
    bool Init(const std::string &object_dir, const std::string &base_compile_cmd);

    bool Reload();

private:
    bool LinkObjectFiles(const std::vector<std::string> &obj_file_list, const std::string &shared_object_path);
    bool RemoveConstructOfGlobalVars(const std::string &shared_object_path);
    bool LoadElfSymbols(const char *elf_file_path);
    bool RelocateVariables(const std::vector<std::string> &obj_file_list, const std::string &shared_object_path);
    void TransferVariables(const std::string &shared_object_path);
    void HookFunctions(const std::string &shared_object_path);

    struct Symbol
    {
        bool operator==(const Symbol &rhs) const
        {
            if (check_hash)
            {
                return hash == rhs.hash && name == rhs.name;
            }
            else
            {
                return name == rhs.name;
            }
        }

        std::string name;
        size_t address = 0;
        size_t transferred_address = 0;
        size_t size = 0;
        bool check_hash = false;
        size_t hash = 0;
    };
    const std::map<std::string, std::vector<Symbol>> *GetHookableFunctionSymbols(const std::string &elf_file_path) const;
    std::map<std::string, std::vector<Symbol>> *GetTransferVariableSymbols(const std::string &elf_file_path);

    const Symbol *GetHookableFunctionSymbol(const std::string &elf_file_path, const std::string &name, bool check_hash, size_t hash) const;
    Symbol *GetTransferVariableSymbol(const std::string &elf_file_path, const std::string &name, bool check_hash, size_t hash);

private:
    std::string m_object_dir;
    std::string m_base_compile_cmd;
    int m_link_times = 0;

    // elf_file_path -> symbol_name -> symbol_list
    std::map<std::string, std::map<std::string, std::vector<Symbol>>> m_hookable_function_symbols;
    std::map<std::string, std::map<std::string, std::vector<Symbol>>> m_transfer_variable_symbols;
};
