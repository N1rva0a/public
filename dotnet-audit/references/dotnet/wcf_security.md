# WCF 安全审计参考（完整版）

> 覆盖 Windows Communication Foundation 全栈安全审计，
> 包含 TypeFilterLevel.Full、元数据暴露、传输安全、反序列化、消息攻击的
> 完整检测命令、成立条件和PoC构造指南。
>
> **激活条件**: Phase 0 RECON 检测到 System.ServiceModel 或 serviceModel 配置。

---

## WCF 侦察（Version Routing 扩展）

```bash
# WCF 服务文件识别
find . -name "*.svc" -o -name "*.svcx" 2>/dev/null | head -10
find . -name "Web.config" -o -name "App.config" 2>/dev/null | \
  xargs grep -l "system.serviceModel\|serviceModel" 2>/dev/null

# 服务契约（接口定义）
grep -rn "\[ServiceContract\]\|\[ServiceBehavior\]\|\[OperationContract\]" \
  --include="*.cs" . 2>/dev/null | head -20

# 数据契约（反序列化入口）
grep -rn "\[DataContract\]\|\[DataMember\]\|\[KnownType\]" \
  --include="*.cs" . 2>/dev/null | head -20

# 绑定类型快速识别
grep -rn "basicHttpBinding\|netTcpBinding\|wsHttpBinding\|netNamedPipeBinding\|netMsmqBinding" \
  --include="*.config" . 2>/dev/null | head -10
```

WCF 绑定安全风险矩阵:

| 绑定类型 | 传输层 | 默认安全 | 主要风险 |
|---------|--------|---------|---------|
| `basicHttpBinding` | HTTP | None | 明文传输 + 无认证 |
| `wsHttpBinding` | HTTP/HTTPS | Message | 消息安全配置不当 |
| `netTcpBinding` | TCP | Transport | 内网暴露面 |
| `netNamedPipeBinding` | 命名管道 | None | 仅本机通信（低风险）|
| `netMsmqBinding` | MSMQ | Message | 消息重放 |
| `webHttpBinding` | HTTP REST | None | 等同普通Web API |

---

## WCF-META-01: 元数据端点暴露（高危）

### 漏洞原理
WCF 的 `serviceMetadata` 行为会发布 WSDL / MEX 端点，
暴露所有服务接口、参数类型、端点地址。攻击者可利用该信息：
1. 完整获取攻击面
2. 生成客户端代理直接调用服务
3. 发现内网地址（WSDL中常包含内网绑定信息）

### 检测

```bash
# 检测 httpGetEnabled
grep -rn "httpGetEnabled\|httpsGetEnabled\|mexHttpBinding\|mexTcpBinding" \
  --include="*.config" . 2>/dev/null

# 检测 ServiceMetadataBehavior（代码配置）
grep -rn "ServiceMetadataBehavior\|HttpGetEnabled\s*=\s*true" --include="*.cs" . 2>/dev/null
```

**高危配置**:
```xml
<serviceMetadata httpGetEnabled="true" httpsGetEnabled="true"/>
<!-- 或 -->
<endpoint address="mex" binding="mexHttpBinding" contract="IMetadataExchange"/>
```

### 成立条件
```
✅ Confirmed: httpGetEnabled=true 或 mexHttpBinding 端点存在 + 生产环境
🔍 Hypothesis: 仅内网暴露（但仍建议关闭）
❌ FP: httpGetEnabled=false 且无 mex 端点
```

### DKTSS 评分
```
Base=5（信息泄露），互联网可达 Friction=0，成熟利用+1
→ DKTSS=6 (Medium)，若同时暴露内网地址则升至 High
```

### PoC（HTTP）
```
GET http://target.com/ServicePath/Service.svc?wsdl
GET http://target.com/ServicePath/Service.svc/mex
→ 返回完整 WSDL 定义 = 成立
```

### 修复
```xml
<!-- 生产环境关闭元数据发布 -->
<serviceMetadata httpGetEnabled="false" httpsGetEnabled="false"/>
<!-- 或直接移除 serviceMetadata 行为 -->
```

---

## WCF-DESER-01: TypeFilterLevel.Full 远程代码执行（Critical）

### 漏洞原理
`TypeFilterLevel.Full` 允许 .NET Remoting 通过 WCF 传输任意类型，
包括 `ISerializable` 实现。配合 `ysoserial.net` 的反序列化 gadget 链，
可直接实现 RCE（与 BinaryFormatter 反序列化同等危害）。

### 检测

```bash
# 配置文件检测
grep -rn "typeFilterLevel.*Full\|TypeFilterLevel\.Full" \
  --include="*.config" --include="*.cs" . 2>/dev/null

# 绑定配置检测
grep -rn "NetTcpContextBinding\|BinaryMessageEncodingBindingElement" \
  --include="*.cs" . 2>/dev/null | head -5
```

**高危配置**:
```xml
<!-- Web.config / App.config -->
<customErrors mode="Off"/>
<system.web>
  <trust level="Full"/>
</system.web>

<!-- WCF 远程通道（.NET Remoting 遗留）-->
<channel ref="tcp" port="8085">
  <serverProviders>
    <formatter ref="binary" typeFilterLevel="Full"/>
  </serverProviders>
</channel>
```

```csharp
// 代码配置（高危）
var binding = new NetTcpBinding();
binding.Security.Mode = SecurityMode.None;
var channel = new ServiceHost(typeof(RemoteService));
channel.AddServiceEndpoint(typeof(IRemoteService), binding, "net.tcp://0.0.0.0:8085/");
```

### 成立条件
```
✅ Confirmed: TypeFilterLevel=Full + 端点可从攻击者网络访问
✅ Confirmed: NetDataContractSerializer 直接反序列化用户可控输入
🔍 Hypothesis: TypeFilterLevel=Full 但仅限内网 + 需要认证
❌ FP: TypeFilterLevel=Low（默认值，仅允许基础类型）
```

### Gadget 链选择（传入 gadget-hunter subagent）
```
Task: gadget-hunter
平台: .NET
反序列化入口: WCF + TypeFilterLevel.Full
序列化格式: BinaryFormatter（NetTcpBinding）
目标框架: .NET Framework {X.Y}
优先gadget: ObjectDataProvider → Process.Start（最通用）
```

### DKTSS 评分
```
Base=10（RCE），Friction按暴露程度，Weapon+1（ysoserial.net直接可用）
→ 互联网+无认证: DKTSS=11→max(10) = Critical
```

---

## WCF-DESER-02: NetDataContractSerializer（无条件 Confirmed）

### 漏洞原理
`NetDataContractSerializer` 在反序列化时保留完整类型信息，
与 `BinaryFormatter` 同等危险，可利用标准 .NET gadget 链实现 RCE。
**任意版本 .NET Framework 均受影响，无版本门控（不适用 BinaryFormatter 的.NET 5+规则）。**

### 检测
```bash
grep -rn "NetDataContractSerializer\|NDCS\b" --include="*.cs" . 2>/dev/null | head -10

# 寻找 ReadObject / Deserialize 调用
grep -rn "\.ReadObject\s*(\|\.Deserialize\s*(" --include="*.cs" . 2>/dev/null | \
  grep -B5 "NetDataContractSerializer" | head -20
```

**高危代码**:
```csharp
// 直接 Confirmed（任何版本）
var ndcs = new NetDataContractSerializer();
var obj = ndcs.ReadObject(userControlledStream);  // 无条件高危
```

### DKTSS 评分
```
Base=10（RCE），与 BinaryFormatter 相同
→ 通常 Critical
```

---

## WCF-SEC-01: 传输安全缺失（中危）

### 检测
```bash
# 找出 security mode="None" 的绑定
grep -rn 'security mode="None"\|<security mode="None"' --include="*.config" . 2>/dev/null

# 找出未配置传输加密的 basicHttpBinding
grep -rn "basicHttpBinding" --include="*.config" . 2>/dev/null | \
  xargs -I{} grep -A10 "{}" 2>/dev/null | grep -v "Transport\|Message" | head -20
```

**高危配置**:
```xml
<basicHttpBinding>
  <binding name="UnsecureBinding">
    <security mode="None"/>  <!-- 明文传输，无认证 -->
  </binding>
</basicHttpBinding>
```

### 成立条件
```
✅ Confirmed: security mode="None" + 接口传输凭证或敏感数据
🔍 Hypothesis: mode="None" 但仅传输公开数据
❌ FP: mode="Transport"（TLS加密）或 mode="Message"（消息加密）
```

### 修复
```xml
<!-- 强制 Transport 安全（HTTPS/TLS）-->
<basicHttpBinding>
  <binding name="SecureBinding">
    <security mode="Transport">
      <transport clientCredentialType="Certificate"/>
    </security>
  </binding>
</basicHttpBinding>
```

---

## WCF-REPLAY-01: 消息重放攻击

### 漏洞原理
WCF 的 `wsHttpBinding` 和 `netTcpBinding` 支持消息安全，但默认不强制开启重放检测。
攻击者可录制并重放认证请求，绕过基于消息签名的认证。

### 检测
```bash
grep -rn "replayDetection\|replayCacheSize\|maxClockSkew" --include="*.config" . 2>/dev/null
# 若无相关配置 → 使用默认值，需检查绑定类型是否受影响

# 检查 wsHttpBinding 消息安全配置
grep -rn "wsHttpBinding" --include="*.config" . 2>/dev/null | \
  xargs -I{} grep -A20 "{}" 2>/dev/null | grep -E "security mode|replayDetection" | head -10
```

**风险配置**:
```xml
<!-- wsHttpBinding 消息安全，未显式开启重放检测 -->
<wsHttpBinding>
  <binding name="WsBinding">
    <security mode="Message">
      <message clientCredentialType="UserName"/>
      <!-- 无 replayDetection 配置 -->
    </security>
  </binding>
</wsHttpBinding>
```

### 成立条件
```
✅ Confirmed: wsHttpBinding/netTcpBinding + 消息安全 + 无显式重放检测
              + 攻击者可截获网络流量（MitM能力）
🔍 Hypothesis: 有重放风险 但 需要网络级别访问
❌ FP: 使用传输安全（Transport mode）而非消息安全
```

---

## WCF-XXE-01: DataContractSerializer XXE

### 漏洞原理
`DataContractSerializer` 与 `XmlSerializer` 内部使用 `XmlDictionaryReader`，
在老旧配置下可能支持 XML 外部实体（XXE）。

### 检测
```bash
grep -rn "DataContractSerializer\|XmlSerializer" --include="*.cs" . 2>/dev/null | head -10
grep -rn "XmlReaderSettings.*DtdProcessing\|XmlResolver" --include="*.cs" . 2>/dev/null | head -5
```

**高危配置**:
```csharp
// 显式启用 DTD 处理的自定义反序列化
var settings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Parse,   // ← 高危（启用DTD）
    XmlResolver = new XmlUrlResolver()     // ← 高危（允许外部实体）
};
var reader = XmlReader.Create(userInput, settings);
var dc = new DataContractSerializer(typeof(MyType));
dc.ReadObject(reader);
```

### 成立条件
```
✅ Confirmed: XmlDictionaryReader 或 DataContractSerializer + DtdProcessing.Parse + 用户可控输入
❌ FP: 未显式配置 DtdProcessing（默认为 Prohibit）
❌ FP: .NET 4.5.2+ 默认 XmlResolver=null（外部实体不可加载）
```

---

## WCF-KNOWN-01: KnownTypes 类型混淆

### 漏洞原理
`[KnownType]` 特性和 `DataContractSerializer` 的 `knownTypes` 参数
控制哪些派生类型可以被反序列化。若 KnownTypes 配置过于宽泛，
攻击者可传入意外的多态类型，触发未预期的业务逻辑。

### 检测
```bash
# 查找 KnownType 配置
grep -rn "\[KnownType\]\|\[KnownType(" --include="*.cs" . 2>/dev/null | head -20

# 查找动态KnownTypes（高危）
grep -rn "DataContractSerializer.*knownTypes\|knownTypes.*new Type\[\]" \
  --include="*.cs" . 2>/dev/null | head -10
```

**风险模式**:
```csharp
// 中危: KnownTypes包含高危类型
[DataContract]
[KnownType(typeof(AdminUser))]     // 普通请求可传入AdminUser类型
[KnownType(typeof(SystemConfig))]  // 系统配置可被外部输入
public class BaseRequest { ... }
```

---

## WCF-AUTH-01: 服务端点匿名访问

### 检测
```bash
# 检查服务行为 — 是否有认证配置
grep -rn "serviceCredentials\|serviceAuthorization\|clientCredentialType" \
  --include="*.config" . 2>/dev/null | head -10

# 无认证的端点
grep -rn "clientCredentialType.*None\|clientCredentialType=\"None\"" \
  --include="*.config" . 2>/dev/null | head -10
```

**高危配置**:
```xml
<bindings>
  <basicHttpBinding>
    <binding>
      <security mode="None">  <!-- 无认证 + 无加密 -->
        <transport clientCredentialType="None"/>
      </security>
    </binding>
  </basicHttpBinding>
</bindings>
```

---

## 标准化漏洞报告补充（WCF 专属字段）

```markdown
#### WCF 专属信息
| 属性 | 值 |
|------|---|
| 绑定类型 | basicHttpBinding / wsHttpBinding / netTcpBinding / ... |
| 服务端点 | {.svc URL 或 net.tcp://地址} |
| 安全模式 | None / Transport / Message / TransportWithMessageCredential |
| 元数据暴露 | 是/否 |
| TypeFilterLevel | Full / Low / 未配置 |

#### PoC（WCF 专属格式）
对于 HTTP-based WCF（basicHttpBinding/wsHttpBinding）:
使用 HTTP Raw 格式（SOAP请求）:
```
POST /ServicePath/Service.svc HTTP/1.1
Host: {targetHostname}
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://tempuri.org/IService/MethodName"

<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <MethodName xmlns="http://tempuri.org/">
      {恶意Payload}
    </MethodName>
  </s:Body>
</s:Envelope>
```

对于 netTcpBinding（非HTTP）:
标注 [非HTTP协议: WCF/TCP]，不阻断 EXPLOIT_QUEUE 入队
```

---

## WCF 安全检查完整清单

```
[WCF_SECURITY_CHECKLIST]
□ 元数据端点（httpGetEnabled/mexBinding）是否关闭？
□ TypeFilterLevel 是否为 Low（禁止 Full）？
□ 所有绑定是否配置传输安全（mode=Transport/Message）？
□ 是否启用消息重放检测（replayDetection）？
□ DataContractSerializer KnownTypes 是否最小化？
□ 是否有客户端认证（clientCredentialType!=None）？
□ DTD 处理是否禁用（DtdProcessing=Prohibit）？
□ NetDataContractSerializer / LosFormatter 是否已废弃替换？
□ WCF 服务是否暴露在公网（还是内网+VPN）？
□ WSDL 是否包含内网地址信息泄露？
```

---

*最后更新: 2026-03-23 | 从38行骨架重建为完整参考，v3.0*
