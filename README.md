# elfpeek

把 ELF 二进制解析成一张结构图：节区/段文件布局地图、入口点、动态依赖与符号摘要，一眼看清二进制骨架。

- 纯 Python 标准库，零第三方依赖
- 只读解析：不加载、不执行二进制中的任何代码
- 32/64 位、大小端 ELF 均支持
- 输出面向逆向与蓝队：终端中文摘要 + 自包含 HTML（纯 SVG 文件布局条带，无 JS，可直接截图存档）+ JSON

## 安装

```bash
pip install elfpeek
```

## 使用

```bash
# 终端输出结构摘要
elfpeek /bin/true

# 导出自包含 HTML 结构图（含节区布局条带，可截图）
elfpeek /bin/true --html report.html

# 导出 JSON 供其他工具消费
elfpeek /bin/true --json report.json
```

## 输出内容

| 板块 | 内容 |
|------|------|
| 文件总览 | 大小、位宽、端序、类型（可执行/共享库/...）、机器架构、入口地址、SONAME |
| 文件布局 | 水平条带，按各节区在文件中的大小比例着色，悬停查看偏移与大小 |
| 程序段 | 类型（LOAD/DYNAMIC/...）、偏移、虚拟地址、文件/内存大小、权限标志 |
| 节区 | 名称、类型（PROGBITS/SYMTAB/...）、偏移、地址、大小、标志（WAX） |
| 动态依赖 | DT_NEEDED 列出的共享库 |
| 动态符号 | 导入函数（未定义）与导出函数（已定义）摘要 |

## 开发

```bash
# 运行测试（含 ELF builder fixture，无需真实系统文件）
python3 -m pytest tests/ -q

# 静态检查
python3 -m ruff check .
```

架构说明：`parse.py` 用 `struct` 纯手工解析 ELF 头、程序头表、节区头表、动态段与符号表（32/64 位、大小端自适应）；`model.py` 是数据模型与类型常量映射；`render/` 负责终端、HTML、JSON 三种渲染；`cli.py` 是入口。

## License

MIT
