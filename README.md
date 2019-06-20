# mipsAudit

## 简介

这是一个MIPS静态汇编审计辅助脚本，使用python编写。

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