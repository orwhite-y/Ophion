# 驱动管理脚本使用说明

## 文件清单

```
F:\winDriver\te\Ophion-master\Ophion-master\
├── manage_driver.bat        # 主管理脚本（需管理员）
├── test_build.bat           # 简单编译测试（无需管理员）
└── test_build_admin.bat     # 自动提权编译测试
```

## 编译测试结果 ✓

**时间**: 2026-09-12 19:09
**状态**: 成功
**产物**:
- Ophion.sys (124 KB)
- TestEptHook.sys (142 KB)
**路径**: F:\winDriver\te\Ophion-master\Ophion-master\build\bin\Debug\

---

## 使用方法

### 1. 完整流程（编译→签名→部署→启动）

**右键管理员运行 CMD**，执行：
```batch
cd F:\winDriver\te\Ophion-master\Ophion-master
manage_driver.bat all
```

这将自动完成：
1. 编译 Debug x64
2. 修补字符串 (Ophion→RMCore)
3. 回退时间到 2015-01-15 签名
4. 恢复时间
5. 部署到 C:\Windows\System32\drivers
6. 创建服务 RMCore + RMCoreTst
7. 启动服务

### 2. 清理（停止+卸载服务）

```batch
manage_driver.bat clean
```

### 3. 单独功能

```batch
# 仅编译
manage_driver.bat build

# 仅签名（需先编译）
manage_driver.bat sign

# 部署+创建服务（需先编译+签名）
manage_driver.bat deploy

# 启动服务
manage_driver.bat start

# 停止服务
manage_driver.bat stop

# 卸载服务
manage_driver.bat uninstall
```

---

## 工作流程详解

### 编译 (build)
- 调用 MSBuild 清理旧输出
- 编译 Ophion.sln (Debug x64)
- 验证产物存在:
  - Ophion.sys
  - TestEptHook.sys

### 签名 (sign)
1. 运行 patch_driver.py 修补驱动字符串
2. 保存当前系统时间
3. 修改系统时间为 2015/1/15
4. 使用 CSignTool 签名两个驱动
5. 恢复系统时间

### 部署 (deploy)
1. 先卸载已存在的旧服务
2. 复制驱动到 C:\Windows\System32\drivers\
3. 创建内核服务:
   - RMCore (Ophion.sys)
   - RMCoreTst (TestEptHook.sys)

### 启动 (start)
按顺序启动:
1. RMCore (Ophion 虚拟化管理程序)
2. RMCoreTst (测试驱动)

检查服务状态并报告

### 停止 (stop)
按反序停止:
1. RMCoreTst (先停测试驱动)
2. RMCore (后停主驱动)

### 卸载 (uninstall)
1. 自动停止两个服务
2. 按反序删除服务
3. 等待 2 秒确保卸载完成

---

## 配置说明

脚本中的路径配置：

```batch
PROJDIR   = F:\winDriver\te\Ophion-master\Ophion-master
SOLUTION  = Ophion.sln
DRVOUT    = build\bin\Debug
DRVDEST   = C:\Windows\System32\drivers
CSIGN     = F:\soft\DSignTool\CSignTool.exe
PY        = C:\Python314\python.exe
PATCH     = F:\work\xg\Cheat Engine\bin\patch_driver.py
MSBUILD   = C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe
```

**驱动文件**:
- Ophion.sys → 服务名 RMCore
- TestEptHook.sys → 服务名 RMCoreTst

**签名日期**: 2015-01-15 (证书有效期内)

---

## 注意事项

1. **管理员权限**
   - 所有操作（除 build）都需要管理员权限
   - 签名需要修改系统时间
   - 服务创建/删除需要管理员权限

2. **服务顺序**
   - 启动: RMCore → RMCoreTst
   - 停止: RMCoreTst → RMCore
   - 卸载: RMCoreTst → RMCore

3. **编译警告**
   - C4819: 文件编码警告（不影响功能）
   - C4996: 使用旧版 API 警告（不影响功能）
   - 这些警告不影响驱动正常编译和运行

4. **时间修改**
   - 签名时会临时修改系统时间
   - 签名完成后自动恢复
   - 确保有修改系统时间的权限

---

## 故障排查

### 编译失败
- 检查 Visual Studio 2022 Professional 是否安装
- 检查 WDK (Windows Driver Kit) 是否安装
- 检查路径: `C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe`

### 签名失败
- 检查 CSignTool 路径: `F:\soft\DSignTool\CSignTool.exe`
- 检查证书是否过期
- 确认有管理员权限修改系统时间

### 服务无法启动
- 检查日志文件（如果有配置）
- 使用 `sc query RMCore` 查看服务状态
- 检查驱动是否正确签名: `sigcheck64.exe -h Ophion.sys`

### 部署失败
- 确认以管理员权限运行
- 检查 System32\drivers 目录权限
- 确认旧服务已完全停止和卸载

---

## 快速参考

| 命令 | 功能 | 需要管理员 |
|------|------|-----------|
| `all` | 完整流程：编译→签名→部署→启动 | ✓ |
| `clean` | 停止+卸载服务 | ✓ |
| `build` | 仅编译项目 | ✗ |
| `sign` | 仅签名驱动 | ✓ |
| `deploy` | 部署+创建服务 | ✓ |
| `start` | 启动服务 | ✓ |
| `stop` | 停止服务 | ✓ |
| `uninstall` | 卸载服务 | ✓ |

---

## 测试确认

✓ 编译功能已测试 (2026-09-12 19:09)
✓ MSBuild 路径已验证
✓ 驱动产物已生成
  - Ophion.sys: 124 KB
  - TestEptHook.sys: 142 KB

**下一步**: 右键管理员运行 CMD，执行 `manage_driver.bat all` 完成完整部署
