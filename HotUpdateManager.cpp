#include "HotUpdateManager.hpp"
#include "ELFReader.h"

#include <cstring>
#include <cstdio>
#include <cassert>
#include <climits>
#include <sstream>
#include <fstream>

#include <dirent.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <link.h>

static std::string get_exe_path()
{
    char str[1024]{};
    char buf[1024]{};

    snprintf(str, sizeof(str), "/proc/%d/exe", getpid());
    readlink(str, buf, sizeof(buf));
    buf[sizeof(buf) - 1] = 0;

    return buf;
}

static std::string get_exe_dir()
{
    char str[1024]{};
    char buf[1024]{};

    snprintf(str, sizeof(str), "/proc/%d/exe", getpid());
    readlink(str, buf, sizeof(buf));
    buf[sizeof(buf) - 1] = 0;

    return dirname(buf);
}

#pragma pack(push, 1)
struct hook_op_struct
{
    uint8_t push_opcode;
    uint32_t push_addr; /* lower 32-bits of the address to jump to */
    uint8_t mov_opcode;
    uint8_t mov_modrm;
    uint8_t mov_sib;
    uint8_t mov_offset;
    uint32_t mov_addr; /* upper 32-bits of the address to jump to */
    uint8_t ret_opcode;
};
#pragma pack(pop)

#define JMP_OPCODE 0xE9
#define PUSH_OPCODE 0x68
#define MOV_OPCODE 0xC7
#define RET_OPCODE 0xC3

#define JMP64_MOV_MODRM 0x44 /* write to address + 1 byte displacement */
#define JMP64_MOV_SIB 0x24   /* write to [rsp] */
#define JMP64_MOV_OFFSET 0x04

static bool make_hook(void *source, void *target)
{
    long pagesize = sysconf(_SC_PAGESIZE);
    void *pageaddr = (void *)((long)source / pagesize * pagesize);
    // void *pageaddr = (void *)((long)source & ~(pagesize - 1));
    if (mprotect(pageaddr, sizeof(hook_op_struct), PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    {
        return false;
    }

    hook_op_struct *hook = (hook_op_struct *)source;

    hook->push_opcode = PUSH_OPCODE;
    hook->push_addr = (uint32_t)(uintptr_t)target; /* truncate */
    hook->mov_opcode = MOV_OPCODE;
    hook->mov_modrm = JMP64_MOV_MODRM;
    hook->mov_sib = JMP64_MOV_SIB;
    hook->mov_offset = JMP64_MOV_OFFSET;
    hook->mov_addr = (uint32_t)(((uintptr_t)target) >> 32);
    hook->ret_opcode = RET_OPCODE;

    return true;
}

static bool endswith(const std::string &s, const std::string &sub)
{
    if (s.rfind(sub) == std::string::npos)
    {
        return false;
    }
    else
    {
        return s.rfind(sub) == (s.length() - sub.length()) ? true : false;
    }
}

static bool startswith(const std::string &s, const std::string &sub)
{
    return s.find(sub) == 0 ? true : false;
}

static void get_obj_file_list(const std::string &dir, std::vector<std::string> &file_list)
{
    file_list.clear();

    DIR *dirp = opendir(dir.c_str());
    if (dirp == NULL)
    {
        perror((dir + " opendir failed").c_str());
        return;
    }

    struct dirent *dirent_data;
    while ((dirent_data = readdir(dirp)) != NULL)
    {
        // printf("%s\n", dirent_data->d_name);
        std::string s(dirent_data->d_name);
        if (endswith(s, ".o"))
            file_list.push_back(dir + "/" + dirent_data->d_name);
    }

    closedir(dirp);
}

static size_t get_base_address(const char *elf_file_path)
{
    struct DlArgument
    {
        size_t base_address = 0;
        std::string path;
    };
    DlArgument dlArgument;
    dlArgument.path = elf_file_path;
    dl_iterate_phdr(
        [](struct dl_phdr_info *info, size_t, void *data)
        {
            auto arg = reinterpret_cast<DlArgument *>(data);
            const char *path = nullptr;
            if (info->dlpi_name && (info->dlpi_name[0] != 0))
            {
                path = info->dlpi_name;
            }
            else
            {
                path = "";
            }
            if (path == arg->path)
            {
                arg->base_address = info->dlpi_addr;
                return 1;
            }
            return 0;
        },
        &dlArgument);

    return dlArgument.base_address;
}

struct MemoryRegion
{
    std::string name;
    uintptr_t regionBegin = 0;
    uintptr_t regionEnd = 0;
    bool isInUse = false;
};

static std::vector<MemoryRegion> getMemoryRegions()
{
    std::vector<MemoryRegion> res;

    auto myPid = getpid();
    std::ifstream f{"/proc/" + std::to_string(myPid) + "/maps"};
    if (!f.is_open())
    {
        return res;
    }

    std::stringstream ss;
    std::string line;
    while (std::getline(f, line))
    {
        MemoryRegion region;

        auto addrDelim = line.find('-');
        auto addrEnd = line.find(' ');
        if (addrDelim == std::string::npos || addrEnd == std::string::npos)
        {
            continue;
        }

        std::istringstream ssline{line};
        std::string w;
        std::vector<std::string> v;
        while (ssline >> w)
        {
            v.push_back(w);
        }
        // const std::vector<std::string> v{
        //     std::istream_iterator<std::string>(ssline), std::istream_iterator<std::string>()};
        if (v.size() >= 6)
        {
            region.name = v[5];
        }

        auto addrBeginStr = "0x" + std::string(line, 0, addrDelim);
        auto addrEndStr = "0x" + std::string(line, addrDelim + 1, addrEnd - addrDelim - 1);
        ss << std::hex << addrBeginStr;
        ss >> region.regionBegin;
        ss.clear();
        ss << std::hex << addrEndStr;
        ss >> region.regionEnd;
        ss.clear();
        region.isInUse = true;

        if (res.empty())
        {
            res.push_back(region);
        }
        else if (res.back().name == region.name && !region.name.empty())
        {
            res.back().regionEnd = region.regionEnd;
        }
        else if (res.back().regionEnd != region.regionBegin)
        {
            MemoryRegion freeRegion;
            freeRegion.regionBegin = res.back().regionEnd;
            freeRegion.regionEnd = region.regionBegin;
            freeRegion.isInUse = false;
            res.push_back(freeRegion);
            res.push_back(region);
        }
        else
        {
            res.push_back(region);
        }
    }

    return res;
}

static uintptr_t findPrefferedBaseAddressForLibrary(const std::vector<std::string> &objectFilePaths)
{
    // Estimating size of the future shared library
    size_t libSize = 0;
    for (const auto &el : objectFilePaths)
    {
        std::ifstream f{el, std::ifstream::ate | std::ifstream::binary};
        libSize += static_cast<size_t>(f.tellg());
    }

    // Trying to find empty space for it
    for (const auto &el : getMemoryRegions())
    {
        if (!el.isInUse && (el.regionEnd - el.regionBegin) > libSize)
        {
            return el.regionBegin;
        }
    }

    // Or just using default relocation
    return 0;
}

static std::string get_real_symbol_name(const std::string &symbol_name)
{
    FILE *symbol_stream = popen((std::string("c++filt ") + symbol_name).c_str(), "r");
    if (symbol_stream == nullptr)
    {
        return symbol_name;
    }

    char real_symbol_name[4096]{};
    fgets(real_symbol_name, sizeof(real_symbol_name), symbol_stream);
    if (real_symbol_name[strlen(real_symbol_name) - 1] == '\n')
        real_symbol_name[strlen(real_symbol_name) - 1] = 0;

    pclose(symbol_stream);

    return real_symbol_name;
}

static std::string get_shared_object_path(int link_times)
{
    std::string path = get_exe_dir();
    path += "/libreload";
    path += std::to_string(link_times);
    path += ".so";
    return path;
}

bool HotUpdateManager::Init(const std::string &object_dir, const std::string &base_compile_cmd)
{
    std::string fix_object_dir = object_dir;
    {
        if (fix_object_dir.empty())
        {
            fix_object_dir = get_exe_dir();
        }
        else
        {
            if (fix_object_dir[0] != '/')
            {
                fix_object_dir = get_exe_dir() + "/" + fix_object_dir;
            }
        }
        std::string mkdir_cmd = "mkdir -p ";
        mkdir_cmd += fix_object_dir;
        system(mkdir_cmd.c_str());
    }
    
    DIR *dirp = opendir(object_dir.c_str());
    if (dirp == NULL)
    {
        printf("HotUpdateManager::init fail, no such object dir: %s\n", object_dir.c_str());
        return false;
    }
    closedir(dirp);

    m_object_dir = fix_object_dir;

    m_base_compile_cmd = base_compile_cmd;

    return this->LoadElfSymbols(get_exe_path().c_str());
}

bool HotUpdateManager::Reload()
{
    std::vector<std::string> obj_file_list;
    get_obj_file_list(m_object_dir, obj_file_list);

    if (obj_file_list.empty())
    {
        printf("HotUpdateManager::Reload fail, no object file exist in directory: %s\n", m_object_dir.c_str());
        return false;
    }

    std::string shared_object_path = get_shared_object_path(m_link_times + 1);
    
    if (!this->LinkObjectFiles(obj_file_list, shared_object_path))
    {
        return false;
    }

    if (!this->RemoveConstructOfGlobalVars(shared_object_path))
    {
        return false;
    }
    
    {
        void *dl_handler = dlopen(shared_object_path.c_str(), RTLD_NOW);
        if (dl_handler == nullptr)
        {
            printf("HotUpdateManager::Reload fail, dlopen failed: %s\n", dlerror());
            return false;
        }
    }
    
    if (!this->LoadElfSymbols(shared_object_path.c_str()))
    {
        return false;
    }

    if (!this->RelocateVariables(obj_file_list, shared_object_path))
    {
        return false;
    }

    this->TransferVariables(shared_object_path);

    this->HookFunctions(shared_object_path);

    return true;
}

bool HotUpdateManager::LinkObjectFiles(const std::vector<std::string> &obj_file_list, const std::string &shared_object_path)
{
    std::string link_cmd = m_base_compile_cmd;

    // 手动指定一个相对当前进程的可用的虚拟地址空间
    // 否则操作系统为了安全起见，可能会分配一个很远的加载地址，导致我们的后续的重定向工作无法正常完成
    size_t libaddress = findPrefferedBaseAddressForLibrary(obj_file_list);
    std::stringstream libaddress_ss;
    libaddress_ss << std::hex << libaddress;
    link_cmd += " -Wl,-Ttext-segment,0x" + libaddress_ss.str();
    link_cmd += " -Wl,-z,max-page-size=0x1000";

    link_cmd += " -shared -o " + shared_object_path + " ";
    for (const std::string &obj_file : obj_file_list)
    {
        link_cmd += obj_file;
        link_cmd += " ";
    }
    int ret = system(link_cmd.c_str());

    if (ret == 0)
    {
        printf("[link success] [%s]\n", link_cmd.c_str());
        ++m_link_times;
    }
    else
    {
        printf("[link fail] %s\n", link_cmd.c_str());
        return false;
    }

    return true;
}

bool HotUpdateManager::RemoveConstructOfGlobalVars(const std::string &shared_object_path)
{
    // 在打开共享库之前，修改编译器生成的为全局对象进行构造和析构的代码
    // 因为我们将全局对象重定位到了主程序的，不希望它再进行构造和析构
    ELFReader elf_reader;
    if (!elf_reader.ReadELFFile(shared_object_path.c_str()))
    {
        return false;
    }

    const ELFReader::Section *text_section = elf_reader.GetSection(".text");
    if (text_section == nullptr)
    {
        printf("HotUpdateManager::Reload for %s, no text section?\n", shared_object_path.c_str());
        return false;
    }
    size_t text_section_vaddress = text_section->section_header.sh_addr;
    size_t text_section_fileoffset = text_section->section_header.sh_offset;

    const std::vector<ELFReader::Symbol> &symbol_list = elf_reader.GetSymbols();
    for (const ELFReader::Symbol &elfsymbol : symbol_list)
    {
        if (elfsymbol.sym_type == STT_FUNC && elfsymbol.sym_bind == STB_LOCAL &&
            startswith(elfsymbol.get_sym_name(elf_reader), "_GLOBAL__sub_I"))
        {
            FILE *fp = fopen(shared_object_path.c_str(), "r+");
            if (fp == nullptr)
            {
                printf("HotUpdateManager::Reload for %s, fopen failed 2: %s\n", shared_object_path.c_str(), strerror(errno));
                return false;
            }

            size_t symbol_fileoffset = text_section_fileoffset + (elfsymbol.sym.st_value - text_section_vaddress);
            if (-1 == fseek(fp, symbol_fileoffset, SEEK_SET))
            {
                fclose(fp);
                printf("HotUpdateManager::Reload for %s, fseek failed: %s\n", shared_object_path.c_str(), strerror(errno));
                return false;
            }

            const char opbuf[] = {(char)RET_OPCODE};
            if (fwrite(opbuf, sizeof(opbuf), 1, fp) != 1)
            {
                fclose(fp);
                printf("HotUpdateManager::Reload for %s, fwrite failed: %s\n", shared_object_path.c_str(), strerror(errno));
                return false;
            }
            fclose(fp);
        }
    }

    return true;
}

bool HotUpdateManager::LoadElfSymbols(const char *elf_file_path)
{
    if (elf_file_path == nullptr)
    {
        printf("HotUpdateManager::LoadElfSymbols: can not parse nullptr to elf_file_path");
        return false;
    }

    ELFReader elf_reader;
    if (!elf_reader.ReadELFFile(elf_file_path))
    {
        return false;
    }

    size_t base_address = 0;
    if (elf_reader.GetHeader().e_type == ET_DYN)
    {
        if (elf_file_path == get_exe_path())
        {
            printf("HotUpdateManager::LoadElfSymbols: executable file must not be a shared object, try to use -no-pie option to build your program\n");
            return false;
        }
        else
        {
            base_address = get_base_address(elf_file_path);
        }
    }
    else if (elf_reader.GetHeader().e_type == ET_EXEC)
    {
        if (get_exe_path() != elf_file_path)
        {
            printf("HotUpdateManager::LoadElfSymbols executable elf file not correct\n");
            return false;
        }
    }
    else
    {
        printf("HotUpdateManager::LoadElfSymbols not supported elf type(only support executable file and shared object): %s\n", elf_reader.GetELFType());
        return false;
    }

    size_t file_hash = 0;
    std::hash<std::string> string_hasher;

    std::map<std::string, std::vector<Symbol>> &hookable_function_symbols = m_hookable_function_symbols[elf_file_path];
    std::map<std::string, std::vector<Symbol>> &transfer_variable_symbols = m_transfer_variable_symbols[elf_file_path];

    hookable_function_symbols.clear();
    transfer_variable_symbols.clear();

    const std::vector<ELFReader::Symbol> &symbol_list = elf_reader.GetSymbols();
    for (const ELFReader::Symbol &elfsymbol : symbol_list)
    {
        const char *symbol_name = elfsymbol.get_sym_name(elf_reader);

        if (elfsymbol.sym_type == STT_FILE)
        {
            file_hash = string_hasher(symbol_name);
            continue;
        }

        Symbol symbol;
        symbol.name = symbol_name;
        symbol.address = elfsymbol.sym.st_value;
        symbol.size = elfsymbol.sym.st_size;
        if (elf_reader.GetHeader().e_type == ET_DYN)
        {
            symbol.address += base_address;
        }

        if (elfsymbol.sym_bind == STB_LOCAL)
        {
            symbol.check_hash = true;
            symbol.hash = file_hash;
        }

        const char *symbol_section = elfsymbol.get_sym_section_desc(elf_reader);
        if (elfsymbol.sym_type == STT_FUNC && (elfsymbol.sym_bind == STB_GLOBAL || elfsymbol.sym_bind == STB_LOCAL) &&
            elfsymbol.sym.st_size > 0 &&
            strcmp(symbol_section, ".text") == 0)
        {
            auto &symbols = hookable_function_symbols[symbol_name];
            for (auto &tmp_symbol : symbols)
            {
                if (tmp_symbol == symbol)
                {
                    printf("HotUpdateManager::LoadElfSymbols fail, your program has symbols with same name and hash (%s)\n", symbol.name.c_str());
                    return false;
                }
            }
            symbols.push_back(symbol);
            // printf("add hookable function: %s\n", symbol_name);
        }
        else if (elfsymbol.sym_type == STT_OBJECT &&
                 elfsymbol.sym_bind == STB_LOCAL &&
                 (strcmp(symbol_section, ".bss") == 0 || strcmp(symbol_section, ".data") == 0))
        {
            auto &symbols = transfer_variable_symbols[symbol_name];
            for (auto &tmp_symbol : symbols)
            {
                if (tmp_symbol == symbol)
                {
                    printf("HotUpdateManager::LoadElfSymbols fail, your program has symbols with same name and hash (%s)\n", symbol.name.c_str());
                    return false;
                }
            }
            symbols.push_back(symbol);
        }
    }

    return true;
}

static bool GetRelocateSymbol(ELFReader::Symbol &symbol, const ELFReader::Relocation &reloc, const ELFReader &elf_reader)
{
    assert(reloc.type != R_X86_64_PC64); // TODO
    if (reloc.type != R_X86_64_PC32)
    {
        // static 变量在x64_64 平台，centos7下的重定位方式
        return false;
    }

    const std::vector<ELFReader::Symbol> &symbols = elf_reader.GetSymbols();

    const ELFReader::Symbol &elfsymbol = symbols.at(reloc.symbol_index);
    std::string sym_name = elfsymbol.get_sym_name(elf_reader);
    if (sym_name == ".bss")
    {
        size_t offset = reloc.rel.r_addend + 4;
        for (const ELFReader::Symbol &var_sym : symbols)
        {
            if (var_sym.sym_type == STT_OBJECT &&
                var_sym.sym_bind == STB_LOCAL &&
                strcmp(var_sym.get_sym_section_desc(elf_reader), ".bss") == 0)
            {
                if (offset == var_sym.sym.st_value)
                {
                    symbol = var_sym;
                    return true;
                }
            }
        }
    }
    else if (sym_name == ".data")
    {
        size_t offset = reloc.rel.r_addend + 4;
        for (const ELFReader::Symbol &var_sym : symbols)
        {
            if (var_sym.sym_type == STT_OBJECT &&
                var_sym.sym_bind == STB_LOCAL &&
                strcmp(var_sym.get_sym_section_desc(elf_reader), ".data") == 0)
            {
                if (offset == var_sym.sym.st_value)
                {
                    symbol = var_sym;
                    return true;
                }
            }
        }
    }

    return false;
}

bool HotUpdateManager::RelocateVariables(const std::vector<std::string> &obj_file_list, const std::string &shared_object_path)
{
    ELFReader so_elf_reader;
    if (!so_elf_reader.ReadELFFile(shared_object_path.c_str()))
    {
        return false;
    }

    size_t base_address = get_base_address(shared_object_path.c_str());

    std::map<std::string, std::vector<Symbol>> so_func_symbols; // symbol_name -> symbol
    std::map<std::string, std::vector<Symbol>> so_var_symbols;
    {
        size_t file_hash = 0;
        std::hash<std::string> string_hasher;

        const std::vector<ELFReader::Symbol> &symbols = so_elf_reader.GetSymbols();
        for (const ELFReader::Symbol &elfsymbol : symbols)
        {
            const char *symbol_name = elfsymbol.get_sym_name(so_elf_reader);

            if (elfsymbol.sym_type == STT_FILE)
            {
                file_hash = string_hasher(symbol_name);
                continue;
            }

            Symbol symbol;
            symbol.name = symbol_name;
            symbol.address = elfsymbol.sym.st_value + base_address;
            symbol.size = elfsymbol.sym.st_size;

            if (elfsymbol.sym_bind == STB_LOCAL)
            {
                symbol.check_hash = true;
                symbol.hash = file_hash;
            }

            const char *symbol_section = elfsymbol.get_sym_section_desc(so_elf_reader);
            if (elfsymbol.sym_type == STT_FUNC && elfsymbol.sym.st_size > 0 && strcmp(symbol_section, ".text") == 0)
            {
                so_func_symbols[symbol_name].push_back(symbol);
            }
            else if (elfsymbol.sym_type == STT_OBJECT && elfsymbol.sym_bind == STB_LOCAL &&
                     (strcmp(symbol_section, ".bss") == 0 || strcmp(symbol_section, ".data") == 0))
            {
                so_var_symbols[symbol_name].push_back(symbol);
            }
        }
    }

    const std::string exe_path = get_exe_path();

    for (const std::string &obj_file : obj_file_list)
    {
        ELFReader elf_reader;
        if (!elf_reader.ReadELFFile(obj_file.c_str()))
        {
            printf("RelocateVariables while ReadELFFile for [%s] fail, WTF???\n", obj_file.c_str());
            continue;
        }

        size_t file_hash = 0;
        std::hash<std::string> string_hasher;

        // offset -> func_symbol
        std::map<size_t, std::vector<Symbol>, bool (*)(int, int)> func_symbols([](int lhs, int rhs)
                                                                               { return lhs > rhs; });
        std::map<std::string, std::vector<Symbol>> var_symbols;

        const std::vector<ELFReader::Symbol> &symbols = elf_reader.GetSymbols();
        for (const ELFReader::Symbol &elfsymbol : symbols)
        {
            const char *symbol_name = elfsymbol.get_sym_name(elf_reader);

            if (elfsymbol.sym_type == STT_FILE)
            {
                file_hash = string_hasher(symbol_name);
                continue;
            }

            Symbol symbol;
            symbol.name = symbol_name;
            symbol.address = elfsymbol.sym.st_value;
            symbol.size = elfsymbol.sym.st_size;
            if (elfsymbol.sym_bind == STB_LOCAL)
            {
                symbol.check_hash = true;
                symbol.hash = file_hash;
            }

            const char *symbol_section = elfsymbol.get_sym_section_desc(elf_reader);
            if (elfsymbol.sym_type == STT_FUNC && elfsymbol.sym.st_size > 0 && strcmp(symbol_section, ".text") == 0)
            {
                func_symbols[symbol.address].push_back(symbol);
            }
            else if (elfsymbol.sym_type == STT_OBJECT && elfsymbol.sym_bind == STB_LOCAL &&
                     (strcmp(symbol_section, ".bss") == 0 || strcmp(symbol_section, ".data") == 0))
            {
                var_symbols[symbol_name].push_back(symbol);
            }
        }

        const std::vector<ELFReader::Relocation> *relocations = elf_reader.GetRelocations(".rela.text");
        if (relocations != nullptr)
        {
            for (const ELFReader::Relocation &reloc : *relocations)
            {
                ELFReader::Symbol reloc_sym;
                if (!GetRelocateSymbol(reloc_sym, reloc, elf_reader))
                {
                    continue;
                }

                size_t offset = reloc.rel.r_offset;
                size_t offset_of_func = 0;
                const char *reloc_symbol_name = reloc_sym.get_sym_name(elf_reader);

                const Symbol *hit_so_func_symbol = nullptr;

                // map 为降序，lower_bound 找首个 <= offset 的函数符号，即是此重定位项所在的函数
                {
                    auto sym_it = func_symbols.lower_bound(offset);
                    if (sym_it != func_symbols.end())
                    {
                        for (const Symbol &func_symbol : sym_it->second)
                        {
                            auto so_func_sym_it = so_func_symbols.find(func_symbol.name);
                            if (so_func_sym_it != so_func_symbols.end())
                            {
                                for (const Symbol &so_func_symbol : so_func_sym_it->second)
                                {
                                    if (func_symbol.check_hash)
                                    {
                                        if (func_symbol.hash == so_func_symbol.hash)
                                        {
                                            hit_so_func_symbol = &so_func_symbol;
                                            offset_of_func = offset - func_symbol.address;
                                            break;
                                        }
                                    }
                                    else
                                    {
                                        hit_so_func_symbol = &so_func_symbol;
                                        offset_of_func = offset - func_symbol.address;
                                        break;
                                    }
                                }
                            }
                            if (hit_so_func_symbol != nullptr)
                            {
                                break;
                            }
                        }
                    }
                }

                if (hit_so_func_symbol == nullptr)
                {
                    printf("[warning] can not relocate(1) [%s] at offset 0x%lx\n", reloc_symbol_name, offset);
                    continue;
                }

                const Symbol *hit_so_var_symbol = nullptr;
                {
                    auto sym_it = var_symbols.find(reloc_symbol_name);
                    if (sym_it != var_symbols.end())
                    {
                        for (const Symbol &var_symbol : sym_it->second)
                        {
                            auto so_var_sym_it = so_var_symbols.find(var_symbol.name);
                            if (so_var_sym_it != so_var_symbols.end())
                            {
                                for (const Symbol &so_var_symbol : so_var_sym_it->second)
                                {
                                    if (var_symbol.check_hash)
                                    {
                                        if (var_symbol.hash == so_var_symbol.hash)
                                        {
                                            hit_so_var_symbol = &so_var_symbol;
                                            break;
                                        }
                                    }
                                    else
                                    {
                                        hit_so_var_symbol = &so_var_symbol;
                                        break;
                                    }
                                }
                            }
                            if (hit_so_var_symbol != nullptr)
                            {
                                break;
                            }
                        }
                    }
                }
                if (hit_so_var_symbol == nullptr)
                {
                    printf("[warning] can not relocate(2) [%s] at offset 0x%lx\n", reloc_symbol_name, offset);
                    continue;
                }

                Symbol *exe_var_symbol = this->GetTransferVariableSymbol(exe_path, hit_so_var_symbol->name, hit_so_var_symbol->check_hash, hit_so_var_symbol->hash);
                if (exe_var_symbol == nullptr)
                {
                    printf("[warning] can not relocate(3) [%s] at offset 0x%lx\n", reloc_symbol_name, offset);
                    continue;
                }

                size_t reloc_address = (size_t)((char *)(hit_so_func_symbol->address) + offset_of_func);
                long operand = exe_var_symbol->address - (reloc_address + 4);
                if (operand < INT_MIN || operand > INT_MAX)
                {
                    printf("[warning] can not relocate(4) [%s] at offset 0x%lx, operand %ld invalid\n", reloc_symbol_name, offset, operand);
                    continue;
                }

                long pagesize = sysconf(_SC_PAGESIZE);
                void *pageaddr = (void *)((long)reloc_address / pagesize * pagesize);
                if (mprotect((void *)pageaddr, 4, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
                {
                    printf("[warning] can not relocate(5) [%s] at offset 0x%lx\n", reloc_symbol_name, offset);
                    continue;
                }

                memcpy((void *)reloc_address, (void *)&operand, 4);
                //printf("HotUpdateManager::RelocateVariables relocate %s at 0x%lx, value is: 0x%lx\n", get_real_symbol_name(reloc_symbol_name).c_str(), reloc_address, operand);
            }
        }
    }

    return true;
}

void HotUpdateManager::TransferVariables(const std::string &shared_object_path)
{
    auto transfer_variable_symbols = this->GetTransferVariableSymbols(shared_object_path);
    if (transfer_variable_symbols != nullptr && !transfer_variable_symbols->empty())
    {
        const std::string exe_path = get_exe_path();

        for (const auto &item : *transfer_variable_symbols)
        {
            for (const auto &symbol : item.second)
            {
                auto old_symbol = this->GetTransferVariableSymbol(exe_path, symbol.name, symbol.check_hash, symbol.hash);

                if (old_symbol != nullptr)
                {
                    if (symbol.size == old_symbol->size)
                    {
                        void *old_symbol_address = (void *)old_symbol->address;
                        if (old_symbol->transferred_address != 0)
                        {
                            old_symbol_address = (void *)old_symbol->transferred_address;
                        }
                        memcpy((void *)symbol.address, (void *)old_symbol_address, symbol.size);

                        (void)get_real_symbol_name;
                        //std::string real_symbol_name = get_real_symbol_name(symbol.name);
                        //printf("variable %s (%s) transfered: old_addr(0x%lx) -> new_addr(0x%lx)\n", symbol.name.c_str(), real_symbol_name.c_str(), old_symbol->address, symbol.address);

                        old_symbol->transferred_address = symbol.address;
                    }
                }
                else
                {
                    printf("[warning] variable [%s] transfer fail: can not find old symbol in executable\n", symbol.name.c_str());
                }
            }
        }
    }
    else
    {
        printf("[warning] can not get transfer variable symbols for %s\n", shared_object_path.c_str());
    }
}

void HotUpdateManager::HookFunctions(const std::string &shared_object_path)
{
    auto hookable_function_symbols = this->GetHookableFunctionSymbols(shared_object_path);
    if (hookable_function_symbols != nullptr && !hookable_function_symbols->empty())
    {
        const std::string exe_path = get_exe_path();

        for (const auto &item : *hookable_function_symbols)
        {
            for (const auto &symbol : item.second)
            {
                const auto *old_symbol = this->GetHookableFunctionSymbol(exe_path, symbol.name, symbol.check_hash, symbol.hash);

                if (old_symbol != nullptr)
                {
                    if (make_hook((void *)old_symbol->address, (void *)symbol.address))
                    {
                        // std::string real_symbol_name = get_real_symbol_name(symbol.name);
                        // printf("function %s (%s) hooked: old_addr(0x%lx) -> new_addr(0x%lx)\n", symbol.name.c_str(), real_symbol_name.c_str(), old_symbol->address, symbol.address);
                    }
                    else
                    {
                        printf("can not reload hookable function: %s\n", symbol.name.c_str());
                    }
                }
                else
                {
                    printf("[warning] function [%s] hook fail: can not find old symbol in executable\n", symbol.name.c_str());
                }
            }
        }
    }
    else
    {
        printf("[warning] can not get hookable functions symbols for %s\n", shared_object_path.c_str());
    }
}

const std::map<std::string, std::vector<HotUpdateManager::Symbol>> *HotUpdateManager::GetHookableFunctionSymbols(const std::string &elf_file_path) const
{
    auto it = m_hookable_function_symbols.find(elf_file_path);
    if (it == m_hookable_function_symbols.end())
    {
        return nullptr;
    }
    return &it->second;
}

std::map<std::string, std::vector<HotUpdateManager::Symbol>> *HotUpdateManager::GetTransferVariableSymbols(const std::string &elf_file_path)
{
    auto it = m_transfer_variable_symbols.find(elf_file_path);
    if (it == m_transfer_variable_symbols.end())
    {
        return nullptr;
    }
    return &it->second;
}

const HotUpdateManager::Symbol *HotUpdateManager::GetHookableFunctionSymbol(const std::string &elf_file_path, const std::string &name, bool check_hash, size_t hash) const
{
    const std::map<std::string, std::vector<HotUpdateManager::Symbol>> *hookable_function_symbols = this->GetHookableFunctionSymbols(elf_file_path);
    if (nullptr == hookable_function_symbols)
    {
        return nullptr;
    }

    auto it = hookable_function_symbols->find(name);
    if (it == hookable_function_symbols->end())
    {
        return nullptr;
    }

    for (const Symbol &symbol : it->second)
    {
        if (check_hash)
        {
            if (symbol.hash == hash)
            {
                return &symbol;
            }
        }
        else
        {
            return &symbol;
        }
    }

    return nullptr;
}

HotUpdateManager::Symbol *HotUpdateManager::GetTransferVariableSymbol(const std::string &elf_file_path, const std::string &name, bool check_hash, size_t hash)
{
    std::map<std::string, std::vector<HotUpdateManager::Symbol>> *transfer_variable_symbols = this->GetTransferVariableSymbols(elf_file_path);
    if (nullptr == transfer_variable_symbols)
    {
        return nullptr;
    }

    auto it = transfer_variable_symbols->find(name);
    if (it == transfer_variable_symbols->end())
    {
        return nullptr;
    }

    for (Symbol &symbol : it->second)
    {
        if (check_hash)
        {
            if (symbol.hash == hash)
            {
                return &symbol;
            }
        }
        else
        {
            return &symbol;
        }
    }

    return nullptr;
}
