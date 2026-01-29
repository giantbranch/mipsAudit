# IDAPython mipsAudit

## 简介

这是一个简单的IDAPython脚本。

进一步来说是MIPS静态汇编审计辅助脚本。

可能会有bug，欢迎大家完善。

> **v3.0 更新**: 支持 IDA 7.x，8.x API 和 Python 3，新增多项高级漏洞检测功能。

## 功能

### 基础功能

1. 找到危险函数的调用处，并且高亮该行（也可以下断点,这个需要自己去源码看吧）
2. 给参数赋值处加上注释
3. 最后以表格的形式输出函数名，调用地址，参数，还有当前函数的缓冲区大小

**大家双击addr那一列的地址，即可跳到对应的地址处**

![17cc62c98820974f8c759dc086dd5acb](17cc62c98820974f8c759dc086dd5acb.png)

![28069d48cf3f357dd83e42406e10d980](28069d48cf3f357dd83e42406e10d980.png)

### v3.0 新增功能

#### 高级漏洞检测

| 检测类型 | 说明 |
|---------|------|
| **命令注入检测** | 追踪 system/popen/execve 参数是否来自外部输入 |
| **栈溢出检测** | 比较目标缓冲区大小与源数据长度 |
| **格式化字符串漏洞** | 检测 %n 写入原语和用户可控格式字符串 |
| **整数溢出检测** | 检测 malloc/calloc 的 size 参数来源和算术运算 |
| **双重释放检测** | 追踪 free() 调用，检测同一指针多次释放 |
| **数据流分析** | 追踪 read/recv 返回数据流向危险函数 |
| **Wrapper函数识别** | 识别封装了危险函数的自定义函数 |

#### 风险等级高亮

| 颜色 | 等级 | 说明 |
|------|------|------|
| 红色 | HIGH | 需要立即关注 |
| 橙色 | MEDIUM | 需要人工复核 |
| 绿色 | LOW | 信息提示 |

#### 结果导出

自动生成带时间戳的 HTML 报告，保存到 IDB 文件所在目录：
```
mipsAudit_results_20260129_143052.html
```

#### 配置文件支持

支持通过 `mipsAudit_config.json` 扩展自定义函数列表：
```json
{
    "dangerous_functions": ["custom_strcpy"],
    "command_execution_function": ["custom_exec"],
    "_comment": "扩展默认函数列表"
}
```

## 审计的危险函数

```python
dangerous_functions = [
    "strcpy", "strcat", "sprintf", "read", "getenv",
    "gets", "scanf", "vscanf", "realpath", "access", "stat", "lstat"
]

attention_function = [
    "memcpy", "strncpy", "sscanf", "strncat", "snprintf",
    "vprintf", "printf", "fprintf", "vfprintf", "vsprintf",
    "vsnprintf", "syslog", "memmove", "bcopy"
]

command_execution_function = [
    "system", "execve", "popen", "unlink",
    "execl", "execle", "execlp", "execv", "execvp",
    "dlopen", "mmap", "mprotect"
]

memory_alloc_functions = [
    "malloc", "calloc", "realloc", "memalign",
    "valloc", "pvalloc", "aligned_alloc", "mmap"
]

memory_free_functions = [
    "free", "cfree", "munmap"
]
```

## 运行流程

```
PHASE 1: Basic Function Audit        # 基础危险函数审计
PHASE 2: Enhanced Vulnerability Detection  # 增强漏洞检测
PHASE 3: Advanced Analysis           # 高级分析（数据流、Wrapper识别）
PHASE 4: Results Summary & Export    # 结果汇总与导出
```

## 使用

### 环境要求

- IDA Pro 7.0+
- Python 3.x（IDA 内置）

### 运行方式

File - Script file

![1561006651468](./1561006651468.png)

选择mipsAudit.py

![1561006737134](./1561006737134.png)

即可看到效果

![mipsAudit](./mipsAudit.png)

双击地址即可跳到对应的代码处

![1561006887117](./1561006887117.png)

## 更新日志

### v3.0 (2026-01)
- 支持 IDA 7.x+ API
- 迁移至 Python 3
- 新增格式化字符串漏洞检测（%n 检测）
- 新增命令注入参数来源追踪
- 新增栈溢出缓冲区大小比较
- 新增整数溢出检测（malloc/calloc size 参数）
- 新增双重释放检测
- 新增数据流分析（read/recv 返回值追踪）
- 新增 Wrapper 函数识别
- 新增基本块分析（修复跨基本块误判）
- 新增 HTML 报告导出（带时间戳）
- 新增外部 JSON 配置文件支持
- 新增扫描进度显示
- 扩展危险函数列表

### v1.0 (2018-05)
- 初始版本 by giantbranch
