#pragma once

#include <cstdio>
#include <string>
#include <vector>
#include <map>

#include <elf.h>

// ELF Format Cheatsheet: 
// https://gist.github.com/x0nu11byt3/bcb35c3de461e5fb66173071a2379779

class ELFReader
{
public:
    // ELF 文件的段
    struct Section
    {
        Elf64_Shdr section_header;
        int number;

        const char *get_name(const ELFReader &reader) const
        {
            return &reader.m_shstrs.at(section_header.sh_name);
        }
    };

    // ELF 文件的符号
    struct Symbol
    {
        Elf64_Sym sym;
        int sym_type;
        int sym_bind;

        const char *get_sym_name(const ELFReader &reader) const
        {
            switch (sym_type)
            {
            case STT_NOTYPE:
            case STT_OBJECT:
            case STT_FUNC:
            case STT_FILE:
                return &reader.m_strs.at(sym.st_name);

            case STT_SECTION:
                return reader.m_sections.at(sym.st_shndx).get_name(reader);
            }
            return "unkown";
        }
    
        const char *get_dynsym_name(const ELFReader &reader) const
        {
            switch (sym_type)
            {
            case STT_NOTYPE:
            case STT_OBJECT:
            case STT_FUNC:
            case STT_FILE:
                return &reader.m_dynstrs.at(sym.st_name);

            case STT_SECTION:
                return reader.m_sections.at(sym.st_shndx).get_name(reader);
            }
            return "unkown";
        }

        std::string get_sym_type_desc() const
        {
            switch(sym_type)
            {
            case STT_NOTYPE:
                return "STT_NOTYPE";
            case STT_OBJECT:
                return "STT_OBJECT";
            case STT_FUNC:
                return "STT_FUNC";
            case STT_SECTION:
                return "STT_SECTION";
            case STT_FILE:
                return "STT_FILE";
            default:
                return std::to_string(sym_type);
            }
        }
    
        std::string get_sym_bind_desc() const
        {
            switch (sym_bind)
            {
                case STB_LOCAL:
                    return "STB_LOCAL";
                case STB_GLOBAL:
                    return "STB_GLOBAL";
                case STB_WEAK:
                    return "STB_WEAK";
                default:
                    return std::to_string(sym_bind);
            }
        }
    
        const char *get_sym_section_desc(const ELFReader &reader) const
        {
            switch (sym.st_shndx)
            {
                case SHN_ABS:
                    return "SHN_ABS";
                case SHN_COMMON:
                    return "SHN_COMMON";
                case SHN_UNDEF:
                    return "SHN_UNDEF";
                default:
                    return reader.m_sections.at(sym.st_shndx).get_name(reader);
            }
        }
    };

	// 需要重定位的条目
	struct Relocation
	{
		Elf64_Rela rel;
		int type;
		int symbol_index;

        const char *get_symbol_name(const ELFReader &reader) const
        {
            return reader.m_symbols.at(symbol_index).get_sym_name(reader);
        }

        const char *get_dynsym_name(const ELFReader &reader) const
        {
            return reader.m_dynsyms.at(symbol_index).get_dynsym_name(reader);
        }

        std::string get_type_desc() const
        {
            switch (type)
            {
                case R_X86_64_32:
                    return "R_X86_64_32";
                case R_X86_64_PC32:
                    return "R_X86_64_PC32";
                case R_X86_64_64:
                    return "R_X86_64_64";
                case R_X86_64_PC64:
                    return "R_X86_64_PC64";
                case R_X86_64_JUMP_SLOT:
                    return "R_X86_64_JUMP_SLOT";
                case R_X86_64_GLOB_DAT:
                    return "R_X86_64_GLOB_DAT";
                default:
                    return std::to_string(type);
            }
        }
	};

    // dynamic 表项
    struct Dynamic
    {
        Elf64_Dyn dyn;
    };

    bool ReadELFFile(FILE *fp);
    bool ReadELFFile(const char *file_path);

    const Elf64_Ehdr &GetHeader() const { return m_header; }
    const char *GetELFClass() const; // ELF64
    const char *GetELFType() const; // .o executable .so

    const std::vector<Section> &GetSections() const { return m_sections; }
    const Section *GetSection(const char *section_name) const;
    const std::vector<Symbol> &GetSymbols() const { return m_symbols; }
    const std::vector<Symbol> &GetDynSyms() const { return m_dynsyms; }
    const std::map<std::string, std::vector<Relocation>> &GetRelocations() const { return m_relocations; }
    const std::vector<Relocation> *GetRelocations(const char *section_name) const;
    const std::vector<Dynamic> &GetDynamics() const { return m_dynamics; }
    const std::string &GetDynamicStrs() const { return m_dynstrs; }

private:
    static bool ReadStrTable(FILE *fp, const Elf64_Shdr &section_header, std::string &str_table);
    static bool ReadSymbolTable(FILE *fp, const Elf64_Shdr &section_header, std::vector<Symbol> &symbols);
	bool ReadRelocationTable(FILE *fp, const Elf64_Shdr &section_header, const std::string &section_name);
    bool ReadDynamicTable(FILE *fp, const Elf64_Shdr &section_header);

private:
    Elf64_Ehdr m_header;
    std::vector<Section> m_sections;
    std::string m_shstrs; // 段表字符串表
    std::string m_strs; // 字符串表
    std::string m_dynstrs; // 动态链接字符串表
    std::vector<Symbol> m_symbols;
    std::vector<Symbol> m_dynsyms;
	std::map<std::string, std::vector<Relocation>> m_relocations;
    std::vector<Dynamic> m_dynamics;
};
