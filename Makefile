CC=g++
CXXFLAGS=-g -Wall -std=c++11 -falign-functions=16

TARGET=main
SOURCES=$(wildcard *.cpp)
OBJS=$(patsubst %.cpp,%.o,$(SOURCES))
C_OBJS=

%.o: %.cpp
	@echo -e "[COMPILING] \c"
	$(CC) $(CXXFLAGS) -c $< -o $@

# 我们需要添加链接选项 -export-dynamic 或 -rdynamic ，从而可以使动态库反向查找主程序中的符号
# see：https://linux.die.net/man/1/ld
# If you use "dlopen" to load a dynamic object which needs to refer back to the symbols defined by the program, 
# rather than some other dynamic object, then you will probably need to use this option when linking the program itself.
# 但由于加了这个符号，我们如果在编译单元中使用非静态全局对象，则它会被重定位到原全局对象，此时将引发多重析构导致程序崩溃！因此还需妥善处理
# On ubuntu, we use -no-pie option to build an EXE file, or it will be a shared object file
$(TARGET): $(OBJS) $(C_OBJS)
	@echo -e "[LINGKING] \c"
		$(CC) $(CXXFLAGS) $(OBJS) $(C_OBJS) -o $(TARGET) -ldl -export-dynamic

ubuntu: $(OBJS) $(C_OBJS)
	@echo -e "[LINGKING] \c"
		$(CC) $(CXXFLAGS) $(OBJS) $(C_OBJS) -o $(TARGET) -ldl -export-dynamic -no-pie

clean:
	@rm -fr *.o main core.* libreload*.so reload

#############################################################
# 使用 gcc -MM *.cpp 创建当前目录下所有CPP文件的依赖关系，然后粘贴在下面
ELFReader.o: ELFReader.cpp ELFReader.h
HotUpdateManager.o: HotUpdateManager.cpp HotUpdateManager.hpp ELFReader.h
HotupdateTest.o: HotupdateTest.cpp HotupdateTest.h HotUpdateManager.hpp \
 Menu.h MenuItem.h Utility.h
main.o: main.cpp HotupdateTest.h HotUpdateManager.hpp
Menu.o: Menu.cpp Menu.h MenuItem.h
MenuItem.o: MenuItem.cpp MenuItem.h
Utility.o: Utility.cpp Utility.h