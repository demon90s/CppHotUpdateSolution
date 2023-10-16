# README

限制：

- 不可以增添、删除函数、成员变量
- 不可以增添、删除局部静态变量

之所以可以对 static local 变量进行 memcpy 来转换，而不会导致初始化的原因是，连同其 guard 变量的内容也被拷贝了。

## 在 dlopen 返回前执行一个函数

只需要在要源代码中添加如同下面的函数：

```c++
static void __attribute__((constructor)) reload_fix()
{
	printf("reload fix\n");
}

```

`__attribute__((constructor))` 声明使得在共享库加载时被执行。
