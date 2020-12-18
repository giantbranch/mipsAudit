# IDAPython mipsAudit

## 更新 2020.12 by t3ls

- 重写了一些函数调用以兼容 IDA 7.5，已测试插件可正常运行在 IDA 7.0, 7.2, 7.5 版本上

- 依赖 `prettytable`，`pip3 install prettytable --target="D:\Program Files\IDA 7.5\python\3"`

- 使用方式修改为：

    1. 将 `mipsAudit.py` 拷贝到 `D:\Program Files\IDA 7.5\plugins` 目录

    2. 启动后在 Edit - Plugins 下点击 mipsAudit 即可（快捷键 Ctrl+Alt+M）

## 简介

这是一个简单的IDAPython脚本。

进一步来说是MIPS静态汇编审计辅助脚本。

可能会有bug，欢迎大家完善。



## 功能

辅助脚本功能如下：

1. 找到危险函数的调用处，并且高亮该行（也可以下断点,这个需要自己去源码看吧）

2. 给参数赋值处加上注释

3. 最后以表格的形式输出函数名，调用地址，参数，还有当前函数的缓冲区大小

**大家双击addr那一列的地址，即可跳到对应的地址处**

![17cc62c98820974f8c759dc086dd5acb](17cc62c98820974f8c759dc086dd5acb.png)

![28069d48cf3f357dd83e42406e10d980](28069d48cf3f357dd83e42406e10d980.png)

## 审计的危险函数如下

```
dangerous_functions = [
    "strcpy", 
    "strcat",  
    "sprintf",
    "read", 
    "getenv"    
]

attention_function = [
    "memcpy",
    "strncpy",
    "sscanf", 
    "strncat", 
    "snprintf",
    "vprintf", 
    "printf"
]

command_execution_function = [
    "system", 
    "execve",
    "popen",
    "unlink"
]
```

## 使用



File - Script file

![1561006651468](./1561006651468.png)

选择mipsAudit.py

![1561006737134](./1561006737134.png)

即可看到效果

![mipsAudit](./mipsAudit.png)

双击地址即可跳到对应的代码处

![1561006887117](./1561006887117.png)
