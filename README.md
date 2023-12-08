# README

A code hot update solution for c++. You have to use this tool only on Linux platform.

I tested it on CentOS7 and github codespace(ubuntu20 maybe?).Therefore it is recommanded you to try it on github codespace.

The core file is: HotUpdateManager.cpp/hpp and ELFReader.cpp/hpp, which you can drag them out to your project.

## Build

on CentOS:

```
make
```

on Ubuntu:

```
make ubuntu
```

## Test and Check usage

Just modify Utility.cpp -> consoleLog while program running, then choose "compile" -> "reload" -> "test".

