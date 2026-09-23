# elfpeek

把 ELF / PE 二进制解析成一张结构图：节区与段布局、内存映射、入口点、动态依赖与符号、加固特性、节区熵与字符串，一眼看清二进制骨架。

- 纯 Python 标准库，零第三方依赖
- 只读解析：不加载、不执行二进制中的任何代码
- ELF 32/64 位、大小端均支持；PE/COFF 32/64 位支持
- 输出面向逆向与蓝队：终端中文摘要 + 自包含 HTML（纯 SVG 布局图，无 JS，可直接截图存档）+ JSON

## 安装

```bash
pip install elfpeek
```

## 使用

```bash
# 终端输出结构摘要（自动识别 ELF / PE）
elfpeek /bin/true
elfpeek sample.exe

# 导出自包含 HTML 结构图（含布局条带，可截图）
elfpeek /bin/true --html report.html

# 导出 JSON 供其他工具消费
elfpeek /bin/true --json report.json
```

## 输出内容

| 板块 | 内容 |
|------|------|
| 文件总览 | 格式、大小、位宽、端序、类型、机器架构、入口地址、SONAME；PE 另含映像基址与子系统 |
| 加固特性 | ELF：PIE / NX / RELRO（完整或部分）/ Canary / FORTIFY / RWX 段；PE：ASLR / DEP / CFG / 高熵 VA / SEHOP / RWX 节区 |
| 文件布局 | 水平条带，按各节区在文件中的大小比例着色 |
| 内存布局 | 按运行时虚拟地址排序的节区/段映射，标注地址区间与权限 |
| 节区表 | 名称、偏移、地址、大小、标志（WAX / CDXR），并附节区熵值（高熵标红提示加壳或压缩） |
| 动态依赖 | ELF：DT_NEEDED 共享库；PE：导入动态库 |
| 符号与函数 | ELF：导入/导出函数摘要；PE：导入函数与导出函数列表 |
| 字符串 | 可打印字符串提取，按 URL / IP / 路径 / 共享库分类 |

## 开发

```bash
# 运行测试（含 ELF 与 PE builder fixture，无需真实系统文件）
python3 -m pytest tests/ -q

# 静态检查
python3 -m ruff check .
```

架构说明：`parse.py` 用 `struct` 纯手工解析 ELF 头、程序头表、节区头表、动态段与符号表（32/64 位、大小端自适应）；`pe.py` 以同样方式解析 PE 的 DOS/COFF/可选头、节区、导入表与导出表，并含 RVA 到文件偏移换算；`checks.py` 负责加固特性判定、节区熵计算与字符串提取分类；`model.py` 是数据模型与类型常量映射；`render/` 负责终端与 HTML 渲染；`cli.py` 按魔数分发到对应解析器。

## License

MIT
