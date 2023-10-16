#include "ELFReader.h"

#include <cstring>
#include <cassert>
#include <iostream>
#include <sstream>

class FilePosRAII
{
public:
    FilePosRAII(const FilePosRAII&) = delete;
    FilePosRAII &operator=(const FilePosRAII&) = delete;
    FilePosRAII(FILE *fp) : m_fp(fp)
    {
        m_old_pos = ftell(fp);
    }
    ~FilePosRAII()
    {
        fseek(m_fp, m_old_pos, SEEK_SET);
    }

private:
    FILE *m_fp;
    long m_old_pos;
};

bool ELFReader::ReadELFFile(FILE *fp)
{
    if (fp == nullptr)
    {
        return false;
    }

    fseek(fp, 0, SEEK_END);
    long file_sz = ftell(fp);
    rewind(fp);

    char header_bytes[5] {};

    if (file_sz < static_cast<long>(sizeof(header_bytes)))
    {
        std::cout << "ELFReader::ReadELFFile failed: file size not correct" << std::endl;
        return false;
    }

    if (fread(&header_bytes, sizeof(header_bytes), 1, fp) != 1)
    {
        perror("ELFReader::ReadELFFile failed: fread failed");
        return false;
    }
    
    // 前四个字节为魔数：0x7F 0x45 0x4c 0x46, 用以识别文件是否为 ELF 文件
    if (!(header_bytes[0] == 0x7f && 
        header_bytes[1] == 'E' && 
        header_bytes[2] == 'L' && 
        header_bytes[3] == 'F'))
    {
        std::cout << "ELFReader::ReadELFFile failed: This file is not an elf file" << std::endl;
        return false;
    }

    // 第五个字节表示 ELF 文件类
    switch (header_bytes[4])
    {
        case 0x01:
            std::cout << "ELFReader::ReadELFFile failed: This file is not an elf64 file" << std::endl; // 我们只研究64位程序
            return false;
            break;

        case 0x02:
            // ELF64
            break;

        default:
            std::cout << "ELFReader::ReadELFFile failed: This file is not an elf64 file 2" << std::endl;
            return false;
            break;
    }

    // 64位程序的 ELF Header 定义
    Elf64_Ehdr header_struct;

    if (file_sz < static_cast<long>(sizeof(header_struct)))
    {
        std::cout << "ELFReader::ReadELFFile failed: file size not correct 2" << std::endl;
        return false;
    }

    rewind(fp);
    if (fread(&header_struct, sizeof(header_struct), 1, fp) != 1)
    {
        perror("ELFReader::ReadELFFile failed: fread failed 2");
        return false;
    }

    if (header_struct.e_machine != EM_X86_64)
    {
        std::cout << "ELFReader::ReadELFFile failed: 文件不是 x86_64 架构" << std::endl; // 我们只研究 X86_64 架构的程序
        return false;
    }

    ELFReader tmp_elf_header;
    tmp_elf_header.m_header = header_struct;

    if (fseek(fp, header_struct.e_shoff, SEEK_SET) != 0 )
    {
        std::cout << "ELFReader::ReadELFFile failed: can not read section header table" << std::endl;
        return false;
    }

    for (int i = 0; i < header_struct.e_shnum; i++)
    {
        Elf64_Shdr section_struct;
        if (fread(&section_struct, sizeof(section_struct), 1, fp) != 1)
        {
            perror("ELFReader::ReadELFFile failed: can not read section header table");
            return false;
        }
        
        Section section;
        section.section_header = section_struct;
        section.number = i;
        tmp_elf_header.m_sections.push_back(section);
    }

    // 读段表字符串表（.shstrtab）
    {
        const Section &section = tmp_elf_header.m_sections.at(header_struct.e_shstrndx);
        if (!ELFReader::ReadStrTable(fp, section.section_header, tmp_elf_header.m_shstrs))
        {
            std::cout << "ELFReader::ReadELFFile failed: ReadStrTable .shstrtab failed" << std::endl;
            return false;
        }
    }

    // 读字符串表（.strtab）
    for (size_t i = 0; i < tmp_elf_header.m_sections.size(); i++)
    {
        const Section &section = tmp_elf_header.m_sections[i];

        if (section.section_header.sh_type == SHT_STRTAB)
        {
            if (strcmp(section.get_name(tmp_elf_header), ".strtab") == 0)
            {
                if (!ELFReader::ReadStrTable(fp, section.section_header, tmp_elf_header.m_strs))
                {
                    std::cout << "ELFReader::ReadELFFile failed: ReadStrTable .strtab failed" << std::endl;
                    return false;
                }
            }
            else if (strcmp(section.get_name(tmp_elf_header), ".dynstr") == 0)
            {
                if (!ELFReader::ReadStrTable(fp, section.section_header, tmp_elf_header.m_dynstrs))
                {
                    std::cout << "ELFReader::ReadELFFile failed: ReadStrTable .dynstr failed" << std::endl;
                    return false;
                }
            }
        }        
    }

    for (const Section &section : tmp_elf_header.m_sections)
    {
        switch (section.section_header.sh_type)
        {
            case SHT_SYMTAB:
                // 读符号表信息
                if (!ELFReader::ReadSymbolTable(fp, section.section_header, tmp_elf_header.m_symbols))
                {
                    std::cout << "ELFReader::ReadELFFile failed: ReadSymbolTable failed" << std::endl;
                    return false;
                }
                break;

            case SHT_DYNSYM:
                // 读动态库符号表信息
                if (!ELFReader::ReadSymbolTable(fp, section.section_header, tmp_elf_header.m_dynsyms))
                {
                    std::cout << "ELFReader::ReadELFFile failed: ReadSymbolTable for .dynsym failed" << std::endl;
                    return false;
                }
                break;
        }
    }

    for (const Section &section : tmp_elf_header.m_sections)
	{
		switch (section.section_header.sh_type)
		{
			case SHT_RELA:
				// 读重定位表信息
				if (!tmp_elf_header.ReadRelocationTable(fp, section.section_header, section.get_name(tmp_elf_header)))
				{
					std::cout << "ELFReader::ReadlELFHeader failed: ReaedRelocationTable failed" << std::endl;
					return false;
				}
				break;
		}
	}

    for (const Section &section : tmp_elf_header.m_sections)
	{
		switch (section.section_header.sh_type)
		{
			case SHT_DYNAMIC:
				// 读 dynamic 表信息
				if (!tmp_elf_header.ReadDynamicTable(fp, section.section_header))
				{
					std::cout << "ELFReader::ReadlELFHeader failed: ReadDynamicTable failed" << std::endl;
					return false;
				}
				break;
		}
	}

    *this = tmp_elf_header;
    return true;
}

bool ELFReader::ReadStrTable(FILE *fp, const Elf64_Shdr &section_header, std::string &str_table)
{
    FilePosRAII fpraii(fp);

    fseek(fp, section_header.sh_offset, SEEK_SET);

    str_table.clear();
    for (size_t i = 0; i < section_header.sh_size; ++i)
    {
        int c = fgetc(fp);
        str_table.push_back((char)c);
    }

    return true;
}

bool ELFReader::ReadSymbolTable(FILE *fp, const Elf64_Shdr &section_header, std::vector<Symbol> &symbols)
{
    FilePosRAII fpraii(fp);

    assert(section_header.sh_entsize == sizeof(Elf64_Sym));

    int entry_num = section_header.sh_size / section_header.sh_entsize;

    fseek(fp, section_header.sh_offset, SEEK_SET);

    for (int i = 0; i < entry_num; i++)
    {
        Elf64_Sym sym;
        if (fread(&sym, sizeof(sym), 1, fp) != 1)
        {
            perror("ELFReader::ReadSymbolTable failed: fread");
            return false;
        }

        Symbol symbol_item;
        symbol_item.sym = sym;        
        
        // sym_info 的低4位表示符号类型
        //symbol_item.sym_type = sym.st_info & 0x0F;
        symbol_item.sym_type = ELF64_ST_TYPE(sym.st_info);

        // sym_info 的高28位表示符号绑定类型
        //symbol_item.sym_bind = (sym.st_info >> 4) & 0x0FFFFFFF;
        symbol_item.sym_bind = ELF64_ST_BIND(sym.st_info);

        symbols.push_back(symbol_item);
    }
    
    return true;
}

bool ELFReader::ReadRelocationTable(FILE *fp, const Elf64_Shdr &section_header, const std::string &section_name)
{
    FilePosRAII fpraii(fp);

    assert(section_header.sh_entsize == sizeof(Elf64_Rela));

    int entry_num = section_header.sh_size / section_header.sh_entsize;

    fseek(fp, section_header.sh_offset, SEEK_SET);

    for (int i = 0; i < entry_num; i++)
    {
        Elf64_Rela rel;
        if (fread(&rel, sizeof(rel), 1, fp) != 1)
        {
            perror("ELFReader::ReadRelocationTable failed: fread");
            return false;
        }

        Relocation rel_item;
        rel_item.rel = rel;        

		// 解析符号表下标
		rel_item.symbol_index = ELF64_R_SYM(rel.r_info);

		// 解析类型
		rel_item.type = ELF64_R_TYPE(rel.r_info);
        
        m_relocations[section_name].push_back(rel_item);
    }
	return true;
}

bool ELFReader::ReadDynamicTable(FILE *fp, const Elf64_Shdr &section_header)
{
    FilePosRAII fpraii(fp);

    assert(section_header.sh_entsize == sizeof(Elf64_Dyn));

    int entry_num = section_header.sh_size / section_header.sh_entsize;

    fseek(fp, section_header.sh_offset, SEEK_SET);

    for (int i = 0; i < entry_num; i++)
    {
        Elf64_Dyn dyn;
        if (fread(&dyn, sizeof(dyn), 1, fp) != 1)
        {
            perror("ELFReader::ReadDynamicTable failed: fread");
            return false;
        }

        Dynamic dynamic_item;
        dynamic_item.dyn = dyn;

        m_dynamics.push_back(dynamic_item);
    }
	return true;
}

const char *ELFReader::GetELFClass() const
{
    switch (m_header.e_ident[4])
    {
        case 0x01:
            return "ELF32";

        case 0x02:
            return "ELF64";

        default:
            return "Unknown";
    }
}

const char *ELFReader::GetELFType() const
{
    switch (m_header.e_type)
    {
        case ET_REL:
            return "ET_REL - 可重定位文件，一般为 .o 文件";

        case ET_EXEC:
            return "ET_EXEC - 可执行文件";

        case ET_DYN:
            return "ET_DYN - 共享目标文件，一般为 .so 文件";

        default:
            return "未知，可能本测试程序未设置";
    }
}

bool ELFReader::ReadELFFile(const char *file_path)
{
    FILE *fp = fopen(file_path, "r");
    if (nullptr == fp)
    {
        printf("ELFReader::ReadELFFile [%s] fail: %s\n", file_path, strerror(errno));
        return false;
    }

    bool ret = this->ReadELFFile(fp);
    fclose(fp);

    return ret;
}

const ELFReader::Section *ELFReader::GetSection(const char *section_name) const
{
    for (const Section &section : m_sections)
    {
        if (strcmp(section.get_name(*this), section_name) == 0)
        {
            return &section;
        }
    }

    return nullptr;
}

const std::vector<ELFReader::Relocation> *ELFReader::GetRelocations(const char *section_name) const
{
    auto it = m_relocations.find(section_name);
    if (it == m_relocations.end())
    {
        return nullptr;
    }

    return &it->second;
}
