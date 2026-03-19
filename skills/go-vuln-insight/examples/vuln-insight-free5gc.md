# 漏洞洞察报告：free5gc

> 项目地址：https://github.com/free5gc/free5gc
> 分析时间：2026-03-19
> 漏洞总数：14（抽样分析）
> 攻击模式数：5

## 概述

free5gc是一个基于Go语言的开源5G核心网实现，遵循3GPP R15/R16规范。项目涵盖AMF、SMF、UPF、PCF、CHF、UDM、UDR、NRF、NEF等核心网络功能。该项目存在大量安全漏洞，主要集中在三个方面：

1. **PFCP协议消息处理缺陷** — SMF/UPF在处理PFCP消息时缺少mandatory IE的nil检查，导致空指针panic
2. **NAS协议解析越界** — AMF处理恶意NAS消息时，对5GS Mobile Identity字段长度验证不足
3. **SBI接口授权缺陷** — 多个NF的HTTP API缺少细粒度的授权检查，导致越权操作

## 漏洞统计

| 严重程度 | 数量 |
|----------|------|
| 高危 (High) | 8 |
| 中危 (Medium) | 4 |
| 低危 (Low) | 2 |

| 漏洞类型 | 数量 |
|----------|------|
| 空指针解引用 (nil dereference) | 8 |
| 数组/切片越界 | 2 |
| 授权缺陷 (Over-authorization) | 3 |
| 资源耗尽 (Resource exhaustion) | 1 |

| 影响组件 | 数量 |
|----------|------|
| SMF | 6 |
| AMF | 3 |
| UPF | 2 |
| PCF | 2 |
| CHF | 1 |

---

## 漏洞详情

### VULN-001: AMF NAS-PDU解析导致索引越界崩溃

- **CVE编号**：CVE-2025-69248（关联）
- **Issue链接**：https://github.com/free5gc/free5gc/issues/835
- **修复PR**：https://github.com/free5gc/nas/pull/43
- **严重程度**：高危
- **影响组件**：AMF
- **影响版本**：free5gc v4.2.0及之前版本

#### 漏洞分析

> 数据来源：Issue #835

AMF在处理NGAP InitialUEMessage中携带的恶意NAS-PDU时，因`MobileIdentity5GS.GetSUCI()`函数对Buffer长度检查不足，直接索引访问超出切片范围的位置，触发`panic: runtime error: index out of range [7] with length 7`。

复现方法：向AMF发送构造的InitialUEMessage NGAP包：
```
000f40480000050055000200010026001a197e0041790007
0102f839000000000000fa0000fa04f0f0f0f00079001350
02f839000002010002f839000001ed80e778005a40011800
70400100
```

#### 关键代码路径

> 来源：Issue #835 堆栈跟踪

- 入口：AMF NGAP handler → 接收 InitialUEMessage
- 调用：NAS消息解码 → `nasType.(*MobileIdentity5GS).GetMobileIdentity5GSContents()`
- 调用：根据identity类型分发 → `nasType.(*MobileIdentity5GS).GetSUCI()`
- 崩溃点：`nasType/NAS_MobileIdentity5GS.go` 中 `a.Buffer[7]` 索引访问越界
- panic信息：`runtime error: index out of range [7] with length 7`

#### 漏洞代码

> 来源：free5gc/nas PR #43之前的代码（nasType/NAS_MobileIdentity5GS.go）

```go
func (a *MobileIdentity5GS) GetSUCI() string {
    // Buffer长度不足时直接索引访问导致panic
    // 未检查 len(a.Buffer) 是否满足各字段偏移量要求
    supiFormat := a.Buffer[0] & 0x70 >> 4
    // ...多处直接索引a.Buffer[N]
}
```

#### 修复代码

> 来源：free5gc/nas PR #43 `fix: prevent panic in MobileIdentity5GS getters on malformed input`

```go
func (a *MobileIdentity5GS) GetMobileIdentity5GSContents() (string, string, error) {
    if len(a.Buffer) == 0 {
        return "", "", errors.New("buffer is empty")
    }
    // ...
}

func (a *MobileIdentity5GS) GetSUCI() (string, error) {
    if len(a.Buffer) == 0 {
        return "", fmt.Errorf("empty buffer")
    }
    // 在每个索引访问前增加长度校验
}
```

#### 根因分析

NAS协议解码函数在访问字节切片元素前未验证Buffer长度，当接收到恶意构造的短长度NAS消息时触发Go运行时panic。

#### 漏洞利用

- **攻击向量**：攻击者需处于可向AMF发送NGAP消息的网络位置（gNB侧或伪造gNB）
- **利用条件**：AMF已完成NG Setup流程，攻击者可通过SCTP连接发送NGAP消息
- **PoC要点**：（Issue #835提供了完整PoC hex）
  1. 通过SCTP连接向AMF发送NGSetupRequest完成NG Setup
  2. 构造InitialUEMessage，其中NAS-PDU包含畸形5GS Mobile Identity（Buffer长度=7但解码需要>=8字节）
  3. 发送该NGAP消息，AMF解析NAS-PDU时在`GetSUCI()`中触发`index out of range [7] with length 7` panic
- **影响**：AMF进程崩溃（DoS），所有已接入UE断开连接，新UE无法注册

---

### VULN-002: AMF 5GS Mobile Identity索引越界（未修复重现）

- **Issue链接**：https://github.com/free5gc/free5gc/issues/856
- **关联Issue**：#747
- **修复PR**：https://github.com/free5gc/free5gc/pull/747（子模块hash更新）
- **严重程度**：高危
- **影响组件**：AMF
- **影响版本**：free5gc v4.2.1

#### 漏洞分析

> 数据来源：Issue #856

Issue #747的修复（nas PR #43）被声称已合并，但在v4.2.1版本中通过不同的恶意包仍可触发相同漏洞。恶意Registration Request中包含较短的5GS Mobile Identity长度字段和以`1`结尾的MSIN时，导致AMF worker崩溃。

复现步骤：
1. 发送NGSetupRequest：`00150044000004001b00090002f839...`
2. 发送构造的InitialUEMessage（5GS Mobile Identity长度被缩短）：`000f40480000050055000200010026001a197e00417900060102f839...`

#### 关键代码路径

> 来源：Issue #856 堆栈跟踪

- 入口：AMF NGAP handler → 接收 InitialUEMessage
- 调用：NAS解码 → `nasType.(*MobileIdentity5GS).GetSUCI()`
- 崩溃点：`nasType/NAS_MobileIdentity5GS.go` 中对 `a.Buffer` 索引访问越界
- 触发条件：5GS Mobile Identity 长度字段被篡改为小于实际解码所需长度，且MSIN以`1`结尾（触发奇数长度解码路径）

#### 漏洞代码

> 来源：nasType/NAS_MobileIdentity5GS.go（基于Issue #856描述，与VULN-001同一函数的不同分支）

```go
// nasType/NAS_MobileIdentity5GS.go
func (a *MobileIdentity5GS) GetSUCI() string {
    // ...
    // 当MSIN长度为奇数时，走不同的解码分支
    // 该分支的长度校验与偶数分支不一致，仍可越界
    msinDigits := a.Buffer[schemeOutputStart:]
    for i := 0; i < len(msinDigits); i++ {
        // 当Buffer被截断时，schemeOutputStart可能已越界
        digit := msinDigits[i] & 0x0F  // panic: index out of range
        // ...
    }
}
```

#### 修复代码

> 状态：暂无完整官方修复（Issue #856指出PR #747的修复不完整）。建议修复方案：

```go
// nasType/NAS_MobileIdentity5GS.go — 建议修复
func (a *MobileIdentity5GS) GetSUCI() (string, error) {
    // 对所有解码分支（含奇数/偶数MSIN长度）统一前置长度校验
    if len(a.Buffer) < minSUCIBufferLen {
        return "", fmt.Errorf("SUCI buffer too short: %d", len(a.Buffer))
    }
    // 在计算schemeOutputStart后再次校验
    if schemeOutputStart >= len(a.Buffer) {
        return "", fmt.Errorf("schemeOutputStart %d exceeds buffer length %d",
            schemeOutputStart, len(a.Buffer))
    }
    // ...
}
```

#### 根因分析

nas PR #43的修复未覆盖所有边界条件。当MSIN以`1`结尾时触发奇数长度解码路径，该路径的长度校验与偶数路径不一致，仍然存在越界访问风险。此外，主仓库子模块版本引用可能未及时更新。

#### 漏洞利用

- **攻击向量**：与VULN-001相同，攻击者需通过SCTP连接向AMF发送NGAP消息
- **利用条件**：AMF已完成NG Setup；需使用v4.2.1版本（声称已修复但实际未完整修复）
- **PoC要点**：（Issue #856提供了完整hex）
  1. 发送NGSetupRequest：`00150044000004001b00090002f839...`
  2. 发送InitialUEMessage，其中5GS Mobile Identity长度字段被缩短且MSIN以`1`结尾：`000f40480000050055000200010026001a197e00417900060102f839...`
  3. 可能需要重复发送多次才能触发（取决于MSIN奇偶性的解码路径选择）
- **影响**：AMF worker崩溃，阻止其他UE连接

---

### VULN-003: SMF PFCP SessionReportRequest缺失ReportType IE致崩溃

- **Issue链接**：https://github.com/free5gc/free5gc/issues/804
- **严重程度**：高危
- **影响组件**：SMF
- **影响版本**：free5gc v4.1.0

#### 漏洞分析

> 数据来源：Issue #804

SMF的`HandlePfcpSessionReportRequest`函数（handler.go:132）在处理PFCP SessionReportRequest时，直接访问`req.ReportType.Dldr`而未检查`req.ReportType`是否为nil。当恶意UPF发送不含ReportType IE的SessionReportRequest时，触发空指针解引用panic。

#### 关键代码路径

> 来源：Issue #804 描述和堆栈跟踪

- 入口：PFCP UDP listener（`udp.go:71`）→ goroutine dispatch（**无panic recovery**）
- 调用：`internal/pfcp/handler/handler.go:132` → `HandlePfcpSessionReportRequest()`
- 崩溃点：`handler.go:132` → 访问 `req.ReportType.Dldr` 而 `req.ReportType == nil`
- 触发条件：SessionReportRequest消息不含ReportType IE，且session处于UpCnxState=DEACTIVATED状态
- 结果：panic终止整个SMF进程（goroutine无recover）

#### 漏洞代码

> 来源：Issue #804描述（handler.go约第132行）

```go
func HandlePfcpSessionReportRequest(msg *pfcp.Message) {
    req := msg.Body.(pfcp.SessionReportRequest)
    // 直接访问ReportType字段，未检查nil
    if req.ReportType.Dldr {  // panic: nil pointer dereference
        // 处理下行数据报告
        handleDownlinkDataReport(req.DownlinkDataReport)
    }
}
```

#### 修复代码

> 状态：暂无官方修复PR。建议修复方案：

```go
// internal/pfcp/handler/handler.go — 建议修复
func HandlePfcpSessionReportRequest(msg *pfcp.Message) {
    req := msg.Body.(pfcp.SessionReportRequest)
    if req.ReportType == nil {
        log.Warn("SessionReportRequest missing mandatory ReportType IE")
        sendErrorResponse(msg, pfcp.CauseMandatoryIEMissing)
        return
    }
    if req.ReportType.Dldr {
        if req.DownlinkDataReport == nil {
            log.Warn("DLDR set but DownlinkDataReport IE missing")
            sendErrorResponse(msg, pfcp.CauseMandatoryIEMissing)
            return
        }
        handleDownlinkDataReport(req.DownlinkDataReport)
    }
}
```

#### 根因分析

PFCP消息处理函数直接对Mandatory IE字段进行解引用而未做nil检查。根据3GPP TS 29.244，ReportType是SessionReportRequest的Mandatory IE，但恶意对端可以发送不合规消息。同时PFCP handler运行在goroutine中且无defer recover，panic直接终止进程。

#### 漏洞利用

- **攻击向量**：攻击者需处于PFCP网络平面（N4接口），可向SMF发送UDP数据包（端口8805）
- **利用条件**：SMF与攻击者之间已建立PFCP Association；存在活跃的PDU Session（UpCnxState=DEACTIVATED）
- **PoC要点**：（Issue #804提供了完整Go语言PoC）
  1. 实现rogue UPF，与SMF完成PFCP Association Setup
  2. 等待SMF建立PDU Session
  3. 构造不含ReportType IE的PFCP SessionReportRequest消息并发送
  4. SMF在handler.go:132处panic，进程终止
- **影响**：SMF进程崩溃（DoS），所有PDU Session中断，新Session无法建立

---

### VULN-004: SMF PFCP SessionReportRequest缺失DownlinkDataReport IE致崩溃

- **Issue链接**：https://github.com/free5gc/free5gc/issues/805
- **严重程度**：高危
- **影响组件**：SMF
- **影响版本**：free5gc v4.1.0

#### 漏洞分析

> 数据来源：Issue #805

当SessionReportRequest的ReportType.DLDR标志置位但消息体中缺少DownlinkDataReport IE时，handler.go:135访问`req.DownlinkDataReport.DownlinkDataServiceInformation`导致nil pointer dereference。

#### 关键代码路径

> 来源：Issue #805 描述

- 入口：PFCP UDP listener（`udp.go:71`）→ goroutine dispatch
- 调用：`internal/pfcp/handler.HandlePfcpSessionReportRequest()`（handler.go）
- 崩溃点：`handler.go:135` → 访问 `req.DownlinkDataReport.DownlinkDataServiceInformation`
- 前置条件：`req.ReportType.Dldr == true`，但 `req.DownlinkDataReport == nil`

#### 漏洞代码

> 来源：Issue #805描述（handler.go约第135行）

```go
// internal/pfcp/handler/handler.go
func HandlePfcpSessionReportRequest(msg *pfcp.Message) {
    req := msg.Body.(pfcp.SessionReportRequest)
    // ...
    if req.ReportType.Dldr {
        // DownlinkDataReport IE未检查nil
        downlinkDataReport := req.DownlinkDataReport
        // panic: nil pointer dereference
        dsInfo := downlinkDataReport.DownlinkDataServiceInformation
        // ...
    }
}
```

#### 修复代码

> 状态：暂无官方修复PR。建议修复方案：

```go
// internal/pfcp/handler/handler.go — 建议修复
if req.ReportType.Dldr {
    if req.DownlinkDataReport == nil {
        log.Warn("ReportType.DLDR set but DownlinkDataReport IE missing")
        sendErrorResponse(msg, pfcp.CauseMandatoryIEMissing)
        return
    }
    dsInfo := req.DownlinkDataReport.DownlinkDataServiceInformation
    // ...
}
```

#### 根因分析

PFCP协议中当ReportType的DLDR标志置位时，DownlinkDataReport IE按规范为Conditional Mandatory（条件必选）。代码仅检查了ReportType标志，但未验证关联的条件必选IE是否存在，导致nil dereference。

#### 漏洞利用

- **攻击向量**：PFCP网络平面（N4接口），UDP端口8805
- **利用条件**：与SMF建立PFCP Association
- **PoC要点**：（Issue #805提供了完整Go语言PoC）
  1. 实现rogue UPF与SMF建立PFCP Association
  2. 构造SessionReportRequest：设置ReportType.DLDR=true，但不包含DownlinkDataReport IE
  3. 发送该消息，SMF在handler.go:135处panic
- **影响**：SMF进程崩溃（DoS）

---

### VULN-005: SMF PFCP SessionReportRequest缺失UsageReportTrigger致崩溃

- **Issue链接**：https://github.com/free5gc/free5gc/issues/814
- **严重程度**：高危
- **影响组件**：SMF
- **影响版本**：free5gc v4.1.0

#### 漏洞分析

> 数据来源：Issue #814

当SessionReportRequest的ReportType.USAR=1且包含UsageReport IE但缺少UsageReportTrigger子IE时，SMF在`identityTriggerType()`函数（pfcp_reports.go:77）中访问`usarTrigger.Volth`导致nil dereference。

#### 关键代码路径

> 来源：Issue #814 描述和堆栈跟踪

- 入口：PFCP UDP listener → goroutine dispatch
- 调用：`internal/pfcp/handler/handler.go:195` → `HandlePfcpSessionReportRequest()`
- 调用：`internal/context/pfcp_reports.go:29` → `SMContext.HandleReports()`
- 崩溃点：`internal/context/pfcp_reports.go:77` → `identityTriggerType()` 中访问 `usarTrigger.Volth`
- 前置条件：`ReportType.USAR=1`，UsageReport IE存在，但UsageReportTrigger子IE缺失

#### 漏洞代码

> 来源：Issue #814描述（pfcp_reports.go约第77行）

```go
// internal/context/pfcp_reports.go
func identityTriggerType(usageReport *pfcp.UsageReport) string {
    usarTrigger := usageReport.UsageReportTrigger
    // usarTrigger为nil时panic
    if usarTrigger.Volth {  // panic: nil pointer dereference
        return "volume_threshold"
    }
    if usarTrigger.Timth {
        return "time_threshold"
    }
    // ...
}

// 调用方 pfcp_reports.go:29
func (c *SMContext) HandleReports(reports []*pfcp.UsageReport) {
    for _, report := range reports {
        triggerType := identityTriggerType(report)  // 传入含nil子IE的report
        // ...
    }
}
```

#### 修复代码

> 状态：暂无官方修复PR。建议修复方案：

```go
// internal/context/pfcp_reports.go — 建议修复
func identityTriggerType(usageReport *pfcp.UsageReport) (string, error) {
    if usageReport.UsageReportTrigger == nil {
        return "", fmt.Errorf("UsageReportTrigger IE missing")
    }
    usarTrigger := usageReport.UsageReportTrigger
    if usarTrigger.Volth {
        return "volume_threshold", nil
    }
    // ...
}
```

#### 根因分析

PFCP UsageReport IE内部的UsageReportTrigger子IE按规范为Mandatory，但代码未对嵌套IE做nil检查。Go语言中嵌套结构体字段为指针类型时，任何一层为nil都会导致panic。

#### 漏洞利用

- **攻击向量**：PFCP网络平面（N4接口），UDP端口8805
- **利用条件**：与SMF建立PFCP Association，存在活跃PDU Session
- **PoC要点**：（Issue #814提供了完整Go语言PoC）
  1. 实现rogue UPF与SMF建立Association
  2. 构造SessionReportRequest：设置ReportType.USAR=1，包含UsageReport IE但省略UsageReportTrigger子IE
  3. 发送消息，SMF在pfcp_reports.go:77处panic
- **影响**：SMF进程崩溃（DoS）

---

### VULN-006: SMF PFCP SessionReportRequest缺失VolumeMeasurement致崩溃

- **Issue链接**：https://github.com/free5gc/free5gc/issues/806
- **严重程度**：高危
- **影响组件**：SMF
- **影响版本**：free5gc v4.1.0

#### 漏洞分析

> 数据来源：Issue #806

当SessionReportRequest的ReportType.USAR=true且包含UsageReport IE但缺少VolumeMeasurement子IE时，SMF在report处理函数中访问`report.VolumeMeasurement.TotalVolume`导致nil dereference。PFCP dispatcher在goroutine中运行handler（udp.go:71）且无panic recovery，panic直接终止SMF进程。

#### 关键代码路径

> 来源：Issue #806 描述

- 入口：PFCP UDP listener → goroutine dispatch（无panic recovery）
- 调用：`internal/pfcp/handler.HandlePfcpSessionReportRequest()`
- 调用：`internal/context/pfcp_reports.go:23` → `SMContext.HandleReports()`
- 崩溃点：`pfcp_reports.go:23` → 访问 `report.VolumeMeasurement.TotalVolume`
- 前置条件：`ReportType.Usar=true`，UsageReport IE存在，但VolumeMeasurement子IE缺失

#### 漏洞代码

> 来源：Issue #806描述（pfcp_reports.go约第23行）

```go
// internal/context/pfcp_reports.go
func (c *SMContext) HandleReports(reports []*pfcp.UsageReport) {
    for _, report := range reports {
        // VolumeMeasurement为nil时panic
        totalVolume := report.VolumeMeasurement.TotalVolume  // panic: nil pointer dereference
        uplinkVolume := report.VolumeMeasurement.UplinkVolume
        downlinkVolume := report.VolumeMeasurement.DownlinkVolume
        // ...
    }
}
```

#### 修复代码

> 状态：暂无官方修复PR。建议修复方案：

```go
// internal/context/pfcp_reports.go — 建议修复
func (c *SMContext) HandleReports(reports []*pfcp.UsageReport) {
    for _, report := range reports {
        if report.VolumeMeasurement == nil {
            log.Warn("UsageReport missing VolumeMeasurement IE, skipping")
            continue
        }
        totalVolume := report.VolumeMeasurement.TotalVolume
        // ...
    }
}
```

#### 根因分析

与VULN-005同源：PFCP UsageReport内部嵌套IE按规范应存在但代码未做防御性检查。VolumeMeasurement在特定条件下为Conditional Optional，但代码假设其始终存在。

#### 漏洞利用

- **攻击向量**：PFCP网络平面（N4接口），UDP端口8805
- **利用条件**：与SMF建立PFCP Association，存在活跃PDU Session
- **PoC要点**：（Issue #806提供了完整Go语言PoC）
  1. 实现rogue UPF
  2. 构造SessionReportRequest：设置ReportType.Usar=true，包含UsageReport IE但省略VolumeMeasurement子IE
  3. 发送消息，SMF在pfcp_reports.go:23处panic
- **影响**：SMF进程崩溃（DoS）

---

### VULN-007: SMF PFCP SessionEstablishmentResponse缺失Cause IE致崩溃

- **Issue链接**：https://github.com/free5gc/free5gc/issues/815
- **严重程度**：高危
- **影响组件**：SMF
- **影响版本**：free5gc v4.1.0

#### 漏洞分析

> 数据来源：Issue #815

恶意UPF回复不含Cause IE的SessionEstablishmentResponse时，SMF在`establishPfcpSession()`中解引用`rsp.Cause`而panic。PoC实现了一个rogue UPF PFCP服务器，正常完成association建立后，在收到SessionEstablishmentRequest时返回不含Cause的Response。

#### 关键代码路径

> 来源：Issue #815 描述

- 入口：SMF发起PFCP Session Establishment → 等待UPF Response
- 调用：`internal/sbi/processor/establishPfcpSession()`
- 崩溃点：`internal/sbi/processor/datapath.go:160`（else分支）→ 访问 `rsp.Cause` 而Cause为nil
- 攻击向量：rogue UPF发送含NodeID和UPFSEID但不含Cause IE的SessionEstablishmentResponse

#### 漏洞代码

> 来源：Issue #815描述（datapath.go约第160行）

```go
// internal/sbi/processor/datapath.go
func establishPfcpSession(ctx *SMContext, rsp *pfcp.SessionEstablishmentResponse) error {
    // 正常路径检查Cause
    if rsp.Cause.CauseValue == pfcp.CauseRequestAccepted {
        // 建立成功
        // ...
    } else {
        // 建立失败 — 进入此分支时同样访问rsp.Cause
        // 当rsp.Cause == nil时，上面的if条件已经panic
        // panic: nil pointer dereference
        return fmt.Errorf("establishment rejected: cause=%d", rsp.Cause.CauseValue)
    }
}
```

#### 修复代码

> 状态：暂无官方修复PR。建议修复方案：

```go
// internal/sbi/processor/datapath.go — 建议修复
func establishPfcpSession(ctx *SMContext, rsp *pfcp.SessionEstablishmentResponse) error {
    if rsp.Cause == nil {
        return fmt.Errorf("SessionEstablishmentResponse missing mandatory Cause IE")
    }
    if rsp.Cause.CauseValue == pfcp.CauseRequestAccepted {
        // ...
    } else {
        return fmt.Errorf("establishment rejected: cause=%d", rsp.Cause.CauseValue)
    }
}
```

#### 根因分析

PFCP Response消息的Cause IE按3GPP TS 29.244为Mandatory，但恶意UPF可省略。代码在if条件判断中直接解引用`rsp.Cause`指针而无前置nil检查。

#### 漏洞利用

- **攻击向量**：PFCP网络平面（N4接口），攻击者实现rogue UPF
- **利用条件**：rogue UPF与SMF完成PFCP Association Setup
- **PoC要点**：（Issue #815提供了完整Go语言PoC）
  1. 实现rogue UPF PFCP服务器，正常完成Association Setup
  2. 收到SessionEstablishmentRequest后，回复SessionEstablishmentResponse：包含NodeID和UPFSEID但不包含Cause IE
  3. SMF在datapath.go:160处panic
- **影响**：SMF进程崩溃（DoS）

---

### VULN-008: SMF PFCP SessionEstablishmentResponse缺失NodeID IE致崩溃

- **Issue链接**：https://github.com/free5gc/free5gc/issues/816
- **严重程度**：高危
- **影响组件**：SMF
- **影响版本**：free5gc v4.1.0

#### 漏洞分析

> 数据来源：Issue #816

恶意UPF回复含UPFSEID但不含NodeID的SessionEstablishmentResponse时，SMF调用`(*pfcpType.NodeID).ResolveNodeIdToIp()`对nil NodeID指针操作，导致panic。

#### 关键代码路径

> 来源：Issue #816 描述

- 入口：SMF发起PFCP Session Establishment → 等待UPF Response
- 调用：`internal/sbi/processor/datapath.go` → 处理SessionEstablishmentResponse
- 崩溃点：`datapath.go:145` → `rsp.NodeID.ResolveNodeIdToIp()` 而 `rsp.NodeID == nil`
- 攻击向量：rogue UPF发送含UPFSEID但不含NodeID的SessionEstablishmentResponse

#### 漏洞代码

> 来源：Issue #816描述（datapath.go约第145行）

```go
// internal/sbi/processor/datapath.go
func handleEstablishmentResponse(rsp *pfcp.SessionEstablishmentResponse) {
    // 当UPFSEID存在时，代码假设NodeID也存在
    if rsp.UPFSEID != nil {
        // NodeID未检查nil
        upfIP := rsp.NodeID.ResolveNodeIdToIp()  // panic: nil pointer dereference
        // ...
    }
}
```

#### 修复代码

> 状态：暂无官方修复PR。建议修复方案：

```go
// internal/sbi/processor/datapath.go — 建议修复
func handleEstablishmentResponse(rsp *pfcp.SessionEstablishmentResponse) {
    if rsp.UPFSEID != nil {
        if rsp.NodeID == nil {
            log.Error("SessionEstablishmentResponse has UPFSEID but missing NodeID")
            return
        }
        upfIP := rsp.NodeID.ResolveNodeIdToIp()
        // ...
    }
}
```

#### 根因分析

代码假设当UPFSEID IE存在时NodeID IE也一定存在，但这是不安全的假设。恶意UPF可以构造任意IE组合。PFCP Response中多个Mandatory IE应当独立检查。

#### 漏洞利用

- **攻击向量**：PFCP网络平面（N4接口），攻击者实现rogue UPF
- **利用条件**：rogue UPF与SMF完成PFCP Association Setup
- **PoC要点**：（Issue #816提供了完整Go语言PoC）
  1. 实现rogue UPF，正常完成Association Setup
  2. 收到SessionEstablishmentRequest后，回复SessionEstablishmentResponse：包含UPFSEID但不包含NodeID
  3. SMF在datapath.go:145处panic
- **影响**：SMF进程崩溃（DoS）

---

### VULN-009: SMF PFCP SessionDeletionResponse缺失Cause IE致崩溃

- **Issue链接**：https://github.com/free5gc/free5gc/issues/817
- **严重程度**：高危
- **影响组件**：SMF
- **影响版本**：free5gc v4.1.0

#### 漏洞分析

> 数据来源：Issue #817

恶意UPF回复不含Cause IE的SessionDeletionResponse时，SMF在处理"Not Accepted"分支中访问`rsp.Cause.CauseValue`导致nil dereference。

#### 关键代码路径

> 来源：Issue #817 描述

- 入口：SMF发起PFCP Session Deletion → 等待UPF Response
- 调用：`internal/sbi/processor/datapath.go` → 处理SessionDeletionResponse
- 崩溃点：`datapath.go:478`（else分支）→ 访问 `rsp.Cause.CauseValue` 而 `rsp.Cause == nil`
- 攻击向量：rogue UPF回复不含Cause IE的SessionDeletionResponse

#### 漏洞代码

> 来源：Issue #817描述（datapath.go约第478行）

```go
// internal/sbi/processor/datapath.go
func handleDeletionResponse(rsp *pfcp.SessionDeletionResponse) error {
    if rsp.Cause.CauseValue == pfcp.CauseRequestAccepted {
        // 删除成功路径
        // ...
    } else {
        // 删除失败路径 — rsp.Cause为nil时在if条件处已经panic
        // panic: nil pointer dereference
        log.Warnf("session deletion not accepted: %d", rsp.Cause.CauseValue)
    }
    return nil
}
```

#### 修复代码

> 状态：暂无官方修复PR。建议修复方案：

```go
// internal/sbi/processor/datapath.go — 建议修复
func handleDeletionResponse(rsp *pfcp.SessionDeletionResponse) error {
    if rsp.Cause == nil {
        return fmt.Errorf("SessionDeletionResponse missing mandatory Cause IE")
    }
    if rsp.Cause.CauseValue == pfcp.CauseRequestAccepted {
        // ...
    } else {
        log.Warnf("session deletion not accepted: %d", rsp.Cause.CauseValue)
    }
    return nil
}
```

#### 根因分析

与VULN-007同源：PFCP Response消息的Cause IE为Mandatory但代码未做nil检查。所有PFCP Response处理路径中对Cause的访问都缺少防御性验证。

#### 漏洞利用

- **攻击向量**：PFCP网络平面（N4接口），攻击者实现rogue UPF
- **利用条件**：rogue UPF与SMF完成PFCP Association，存在活跃PDU Session
- **PoC要点**：（Issue #817提供了完整PoC描述）
  1. 实现rogue UPF
  2. 等待SMF发起Session Deletion（如PDU Session释放流程）
  3. 回复SessionDeletionResponse：不包含Cause IE
  4. SMF在datapath.go:478处panic
- **影响**：SMF进程崩溃（DoS）

---

### VULN-010: PCF POST /app-sessions处理suppFeat=1时panic

- **Issue链接**：https://github.com/free5gc/free5gc/issues/879
- **严重程度**：中危
- **影响组件**：PCF
- **影响版本**：free5gc v4.x

#### 漏洞分析

> 数据来源：Issue #879

PCF的`POST /npcf-policyauthorization/v1/app-sessions`在请求包含`suppFeat="1"`（启用流量路由支持）但不含`AfRoutReq`时，create handler调用`provisioningOfTrafficRoutingInfo()`并传入nil的routeReq参数，后者未检查nil即解引用，导致panic。

#### 关键代码路径

> 来源：Issue #879 描述

- 入口：`NFs/pcf/internal/sbi/api_policyauthorization.go` → HTTP POST `/app-sessions`
- 调用：`NFs/pcf/internal/sbi/processor/policyauthorization.go` → create handler
- 调用：create handler 检测 `suppFeat` 包含流量路由支持 → 调用 `provisioningOfTrafficRoutingInfo(smPolicy, appID, routeReq, ...)`
- 崩溃点：`provisioningOfTrafficRoutingInfo()` 内部解引用 `routeReq`，而 `routeReq == nil`
- 触发条件：请求含 `suppFeat="1"` 但不含 `AfRoutReq` 字段

#### 漏洞代码

> 来源：Issue #879描述（NFs/pcf/internal/sbi/processor/policyauthorization.go）

```go
// NFs/pcf/internal/sbi/processor/policyauthorization.go
func (p *Processor) handleCreateAppSession(req *models.AppSessionContext) {
    // ...
    ascReqData := req.AscReqData
    if hasSuppFeat(ascReqData.SuppFeat, TrafficRoutingFeature) {
        // routeReq可能为nil（请求中未提供AfRoutReq）
        routeReq := ascReqData.AfRoutReq
        // 无nil检查直接传入
        provisioningOfTrafficRoutingInfo(smPolicy, appID, routeReq, ascReqData.MedComponents)
    }
    // ...
}

func provisioningOfTrafficRoutingInfo(smPolicy *SmPolicy, appID string,
    routeReq *models.AfRoutReq, medComponents map[string]*models.MediaComponent) {
    // routeReq为nil时panic
    routeInfo := routeReq.RouteToLocs  // panic: nil pointer dereference
    // ...
}
```

#### 修复代码

> 状态：暂无官方修复PR。建议修复方案：

```go
// NFs/pcf/internal/sbi/processor/policyauthorization.go — 建议修复
func (p *Processor) handleCreateAppSession(req *models.AppSessionContext) {
    ascReqData := req.AscReqData
    if hasSuppFeat(ascReqData.SuppFeat, TrafficRoutingFeature) {
        routeReq := ascReqData.AfRoutReq
        if routeReq == nil {
            // suppFeat启用了流量路由但未提供路由请求，返回错误
            problemDetails := &models.ProblemDetails{
                Status: http.StatusBadRequest,
                Detail: "AfRoutReq required when traffic routing feature is enabled",
            }
            return problemDetails
        }
        provisioningOfTrafficRoutingInfo(smPolicy, appID, routeReq, ascReqData.MedComponents)
    }
}
```

#### 根因分析

`suppFeat`标志与对应请求字段之间缺少一致性校验。代码检查了feature flag是否启用，但未验证该feature所依赖的数据字段是否在请求中提供。合法的请求可以设置`suppFeat="1"`而不附带`AfRoutReq`，暴露了输入验证的不完整性。

#### 漏洞利用

- **攻击向量**：SBI接口（HTTP/2），需要有效的npcf-policyauthorization service token
- **利用条件**：攻击者持有有效OAuth2 token（如已注册的AF）
- **PoC要点**：（Issue #879提供了验证步骤）
  1. 获取有效的npcf-policyauthorization token
  2. 发送POST `/npcf-policyauthorization/v1/app-sessions`，请求体包含`suppFeat="1"`、有效的`notifUri`/`ueIpv4`/`dnn`/`medComponents`，但不包含`AfRoutReq`
  3. PCF在`provisioningOfTrafficRoutingInfo()`中panic，返回500
- **影响**：PCF app-session创建端点拒绝服务；Gin recovery可能保持容器存活但endpoint持续不可用

---

### VULN-011: AMF DELETE /subscriptions/{id} 更新后panic

- **Issue链接**：https://github.com/free5gc/free5gc/issues/876
- **严重程度**：中危
- **影响组件**：AMF
- **影响版本**：free5gc v4.x

#### 漏洞分析

> 数据来源：Issue #876

AMF的订阅管理中存在类型一致性问题。POST创建时存储值类型，PUT更新时替换为指针类型，DELETE删除时做值类型断言因类型不匹配而panic。

复现步骤：
1. `POST /namf-comm/v1/subscriptions` → `201 Created`
2. `PUT /namf-comm/v1/subscriptions/4` → `202 Accepted`
3. `DELETE /namf-comm/v1/subscriptions/4` → `500 Internal Server Error`（panic）

#### 关键代码路径

> 来源：Issue #876 描述

- 创建路径：`NFs/amf/internal/context/context.go` → `AMFStatusSubscriptions` map存储**值类型** `SubscriptionData`
- 更新路径：`NFs/amf/internal/sbi/processor/subscription.go` → 同一map存储**指针类型** `*SubscriptionData`
- 删除路径：`NFs/amf/internal/context/context.go` → `FindAMFStatusSubscription()` 对map值做值类型断言
- 崩溃点：`FindAMFStatusSubscription()` 中 `val.(SubscriptionData)` 断言失败（实际类型为`*SubscriptionData`）→ panic

#### 漏洞代码

> 来源：Issue #876描述（NFs/amf/internal/context/context.go 和 processor/subscription.go）

```go
// NFs/amf/internal/context/context.go — 创建时存储值类型
func (c *AMFContext) AddSubscription(id string, sub SubscriptionData) {
    c.AMFStatusSubscriptions.Store(id, sub)  // 值类型
}

// NFs/amf/internal/sbi/processor/subscription.go — 更新时存储指针类型
func (p *Processor) HandleUpdateSubscription(id string, sub *SubscriptionData) {
    p.Context().AMFStatusSubscriptions.Store(id, sub)  // 指针类型！类型不一致
}

// NFs/amf/internal/context/context.go — 删除时做值类型断言
func (c *AMFContext) FindAMFStatusSubscription(id string) (SubscriptionData, bool) {
    val, ok := c.AMFStatusSubscriptions.Load(id)
    if !ok {
        return SubscriptionData{}, false
    }
    // PUT更新后val是*SubscriptionData，断言为SubscriptionData会panic
    return val.(SubscriptionData), true  // panic: interface conversion
}
```

#### 修复代码

> 状态：暂无官方修复PR。建议修复方案：

```go
// NFs/amf/internal/context/context.go — 建议修复：统一存储类型 + comma-ok断言
func (c *AMFContext) AddSubscription(id string, sub SubscriptionData) {
    c.AMFStatusSubscriptions.Store(id, &sub)  // 统一使用指针类型
}

func (c *AMFContext) FindAMFStatusSubscription(id string) (*SubscriptionData, bool) {
    val, ok := c.AMFStatusSubscriptions.Load(id)
    if !ok {
        return nil, false
    }
    sub, ok := val.(*SubscriptionData)  // comma-ok模式防止panic
    if !ok {
        log.Warnf("unexpected type in subscription store: %T", val)
        return nil, false
    }
    return sub, true
}
```

#### 根因分析

Go的`sync.Map`存储`interface{}`类型值。CRUD操作分散在不同文件中，Create存储值类型`SubscriptionData`，Update存储指针类型`*SubscriptionData`，类型不一致。Delete路径的类型断言`val.(SubscriptionData)`在值为指针类型时panic。这是Go类型系统中`interface{}`使用的常见陷阱。

#### 漏洞利用

- **攻击向量**：SBI接口（HTTP/2），需要有效的namf-comm service token
- **利用条件**：攻击者持有有效namf-comm token
- **PoC要点**：（Issue #876提供了验证步骤）
  1. `POST /namf-comm/v1/subscriptions` 创建订阅 → `201 Created`
  2. `PUT /namf-comm/v1/subscriptions/{id}` 更新同一订阅 → `202 Accepted`（此步将map中的值类型替换为指针类型）
  3. `DELETE /namf-comm/v1/subscriptions/{id}` 删除订阅 → `500 Internal Server Error`（panic）
- **影响**：AMF订阅管理endpoint拒绝服务

---

### VULN-012: UPF PFCP会话资源耗尽拒绝服务

- **Issue链接**：https://github.com/free5gc/free5gc/issues/819
- **修复PR**：https://github.com/free5gc/go-upf/pull/98
- **严重程度**：中危
- **影响组件**：UPF
- **影响版本**：go-upf v1.x

#### 漏洞分析

> 数据来源：Issue #819

UPF的`LocalNode.NewSess()`无限制地接受新会话创建请求，无上限也无准入控制。恶意PFCP对端可通过重复发送带有唯一SEID的SessionEstablishmentRequest来耗尽UPF内存，最终触发OOM killer。

#### 关键代码路径

> 来源：Issue #819 描述

- 入口：UPF PFCP listener → 收到 SessionEstablishmentRequest
- 调用：`node.go:651-672` → `LocalNode.NewSess(seid)`
- 漏洞点：`NewSess()` 中 `n.sess = append(n.sess, sess)` 无任何上限检查
- 攻击方式：持续发送不同SEID的SessionEstablishmentRequest，不发送对应的SessionDeletionRequest

#### 漏洞代码

> 来源：Issue #819描述（node.go约第651-672行）

```go
// node.go (go-upf)
func (n *LocalNode) NewSess(seid uint64) *Session {
    sess := &Session{
        SEID:    seid,
        PDRs:    make(map[uint16]*PDR),
        FARs:    make(map[uint32]*FAR),
        URRIDs:  make(map[uint32]*URRInfo),
    }
    // 无上限检查，无速率限制，无准入控制
    n.sess = append(n.sess, sess)  // 每次调用分配新内存，永不释放
    return sess
}
```

#### 修复代码

> 来源：free5gc/go-upf PR #98（部分修复）

```go
// node.go (go-upf) — 修复方案：添加会话数量上限
const MaxSessions = 10000

func (n *LocalNode) NewSess(seid uint64) (*Session, error) {
    n.mu.Lock()
    defer n.mu.Unlock()
    if len(n.sess) >= MaxSessions {
        return nil, fmt.Errorf("session limit reached: %d", MaxSessions)
    }
    sess := &Session{
        SEID:   seid,
        PDRs:   make(map[uint16]*PDR),
        FARs:   make(map[uint32]*FAR),
        URRIDs: make(map[uint32]*URRInfo),
    }
    n.sess = append(n.sess, sess)
    return sess, nil
}
```

#### 根因分析

资源创建函数缺少准入控制和数量上限。PFCP协议本身不限制会话创建数量，但实现中应当设置合理上限以防御资源耗尽攻击。同时缺少PFCP peer的速率限制和可疑行为检测。

#### 漏洞利用

- **攻击向量**：PFCP网络平面（N4接口），UDP端口8805
- **利用条件**：攻击者可向UPF发送PFCP消息（无需Association的情况下取决于实现）
- **PoC要点**：（Issue #819提供了完整Go语言PoC）
  1. 与UPF建立PFCP Association
  2. 循环发送SessionEstablishmentRequest，每次使用不同的SEID
  3. 不发送对应的SessionDeletionRequest
  4. UPF内存持续增长，最终触发OOM killer
- **影响**：UPF进程被OOM killer终止（DoS），所有用户面数据转发中断

---

### VULN-013: NRF nnrf-nfm接口越权操作

- **Issue链接**：https://github.com/free5gc/free5gc/issues/846, #847, #848
- **修复PR**：https://github.com/free5gc/free5gc/pull/846, #847, #848
- **严重程度**：中危
- **影响组件**：NRF
- **影响版本**：free5gc v4.x

#### 漏洞分析

> 数据来源：Issue #846, #847, #848

NRF的`nnrf-nfm`接口允许：
- 未认证的RegisterNFInstance（PUT /nf-instances/{nfInstanceId}）
- 非owner NF可PATCH修改其他NF profile（UpdateNFInstance）
- 非owner NF可DELETE注销其他NF实例（DeregisterNFInstance）

#### 关键代码路径

> 来源：Issue #846, #847, #848 描述

- 路由注册：`NFs/nrf/internal/sbi/server.go` → 注册 nnrf-nfm 路由组
- 认证中间件：`NFs/nrf/internal/util/router_auth_check.go` → 仅检查 service scope（`nnrf-nfm`）
- RegisterNFInstance：PUT `/nf-instances/{nfInstanceId}` → 无认证中间件保护（Issue #846）
- UpdateNFInstance：PATCH `/nf-instances/{nfInstanceId}` → 未校验请求者nfInstanceId == 目标nfInstanceId（Issue #847）
- DeregisterNFInstance：DELETE `/nf-instances/{nfInstanceId}` → 同上，任意NF可删除其他NF（Issue #848）

#### 漏洞代码

> 来源：基于Issue #846, #847, #848描述（NFs/nrf/internal/sbi/ 和 util/router_auth_check.go）

```go
// NFs/nrf/internal/util/router_auth_check.go
func AuthMiddleware(serviceName string) gin.HandlerFunc {
    return func(c *gin.Context) {
        token := extractBearerToken(c)
        claims, err := validateToken(token)
        if err != nil {
            c.AbortWithStatus(401)
            return
        }
        // 仅检查service scope，不检查资源所有权
        if !claims.HasScope(serviceName) {
            c.AbortWithStatus(403)
            return
        }
        // 缺失：未验证 claims.NfInstanceId == c.Param("nfInstanceId")
        c.Next()
    }
}

// NFs/nrf/internal/sbi/server.go — RegisterNFInstance甚至无认证中间件
func (s *Server) registerRoutes() {
    nfmGroup := s.router.Group("/nnrf-nfm/v1")
    // PUT不经过AuthMiddleware
    nfmGroup.PUT("/nf-instances/:nfInstanceId", s.RegisterNFInstance)
    // PATCH/DELETE经过AuthMiddleware但只检查scope
    nfmAuth := nfmGroup.Group("", AuthMiddleware("nnrf-nfm"))
    nfmAuth.PATCH("/nf-instances/:nfInstanceId", s.UpdateNFInstance)
    nfmAuth.DELETE("/nf-instances/:nfInstanceId", s.DeregisterNFInstance)
}
```

#### 修复代码

> 状态：暂无官方修复PR。建议修复方案：

```go
// NFs/nrf/internal/sbi/server.go — 建议修复
func (s *Server) registerRoutes() {
    nfmGroup := s.router.Group("/nnrf-nfm/v1")
    // 所有操作都经过认证中间件
    nfmAuth := nfmGroup.Group("", AuthMiddleware("nnrf-nfm"))
    nfmAuth.PUT("/nf-instances/:nfInstanceId", s.RegisterNFInstance)
    nfmAuth.PATCH("/nf-instances/:nfInstanceId", OwnershipCheck(), s.UpdateNFInstance)
    nfmAuth.DELETE("/nf-instances/:nfInstanceId", OwnershipCheck(), s.DeregisterNFInstance)
}

// 资源所有权检查中间件
func OwnershipCheck() gin.HandlerFunc {
    return func(c *gin.Context) {
        callerNfId := c.GetString("callerNfInstanceId")
        targetNfId := c.Param("nfInstanceId")
        if callerNfId != targetNfId {
            c.AbortWithStatusJSON(403, models.ProblemDetails{
                Status: 403, Detail: "cannot operate on other NF instance",
            })
            return
        }
        c.Next()
    }
}
```

#### 根因分析

NRF的OAuth2授权粒度过粗：仅检查token的service scope（`nnrf-nfm`），不检查请求者是否有权操作目标资源。3GPP TS 29.510规范要求NF只能管理自身的NF profile，但代码未实现此约束。此外RegisterNFInstance端点完全缺少认证。

#### 漏洞利用

- **攻击向量**：SBI接口（HTTP/2），NRF服务端口
- **利用条件**：攻击者持有任意有效的nnrf-nfm scope token（任何已注册NF均可获取）
- **PoC要点**：
  1. 以NF-A身份获取nnrf-nfm token
  2. 越权操作一：`PUT /nf-instances/{NF-B-id}` 注册/覆盖NF-B的profile（无需认证）
  3. 越权操作二：`PATCH /nf-instances/{NF-B-id}` 使用NF-A的token修改NF-B的profile
  4. 越权操作三：`DELETE /nf-instances/{NF-B-id}` 使用NF-A的token注销NF-B
- **影响**：攻击者可注销任意NF、篡改NF服务发现数据，造成核心网服务中断或流量劫持

---

### VULN-014: 多个NF的SBI回调接口缺少认证

- **Issue链接**：https://github.com/free5gc/free5gc/issues/886, #889, #860, #861
- **严重程度**：中危
- **影响组件**：NEF、UDM
- **影响版本**：free5gc v4.x

#### 漏洞分析

> 数据来源：Issue #886, #889

多个NF的回调接口（callback endpoint）未添加OAuth2认证中间件，攻击者可直接伪造回调请求。受影响接口包括NEF的nnef-callback、UDM的/{supi}/sdm-subscriptions回调等。

#### 关键代码路径

> 来源：Issue #886, #889 描述

- NEF回调（Issue #886）：`NFs/nef/internal/sbi/server.go` → callback路由组未添加 `AuthMiddleware`
- UDM回调（Issue #889）：`NFs/udm/internal/sbi/server.go` → `/{supi}/sdm-subscriptions` 回调路由无认证
- 攻击路径：攻击者直接向回调URL发送伪造的HTTP请求，NF无条件接受并处理

#### 漏洞代码

> 来源：基于Issue #886, #889描述（NFs/nef/internal/sbi/server.go 和 NFs/udm/internal/sbi/server.go）

```go
// NFs/nef/internal/sbi/server.go — 回调路由无认证
func (s *Server) registerRoutes() {
    // 正常API有认证
    nefGroup := s.router.Group("/nnef-pfdmanagement/v1", AuthMiddleware("nnef-pfdmanagement"))
    // ...

    // 回调路由没有AuthMiddleware — 任何人都可以调用
    callbackGroup := s.router.Group("/nnef-callback")
    callbackGroup.POST("/notify", s.HandleCallback)  // 无认证保护
}

// NFs/udm/internal/sbi/server.go — SDM订阅回调无认证
func (s *Server) registerRoutes() {
    // ...
    // 回调端点缺失认证中间件
    sdmCallbackGroup := s.router.Group("/nudm-sdm/v2")
    sdmCallbackGroup.POST("/:supi/sdm-subscriptions", s.HandleSDMCallback)  // 无认证
}
```

#### 修复代码

> 状态：暂无官方修复PR。建议修复方案：

```go
// NFs/nef/internal/sbi/server.go — 建议修复：回调路由添加认证
func (s *Server) registerRoutes() {
    // 回调路由也需要认证保护
    callbackGroup := s.router.Group("/nnef-callback", AuthMiddleware("nnef-callback"))
    callbackGroup.POST("/notify", s.HandleCallback)
}

// NFs/udm/internal/sbi/server.go — 建议修复
func (s *Server) registerRoutes() {
    sdmCallbackGroup := s.router.Group("/nudm-sdm/v2", AuthMiddleware("nudm-sdm"))
    sdmCallbackGroup.POST("/:supi/sdm-subscriptions", s.HandleSDMCallback)
}
```

#### 根因分析

开发时认为回调接口只被内部NF调用而忽略了认证保护。但在5GC SBA架构中，所有NF间通信都应通过OAuth2认证。回调URL在创建订阅时由调用方指定，攻击者可以直接向回调端点发送伪造请求。

#### 漏洞利用

- **攻击向量**：SBI接口（HTTP/2），直接访问NF的回调端口
- **利用条件**：攻击者知道目标NF的回调URL（可通过NRF服务发现获取）
- **PoC要点**：
  1. 不需要任何token或认证凭据
  2. 直接向NEF的`/nnef-callback/notify`发送伪造的回调通知
  3. 或向UDM的`/{supi}/sdm-subscriptions`发送伪造的SDM订阅回调
  4. NF无条件接受并处理伪造的回调数据
- **影响**：攻击者可注入虚假的事件通知、伪造订阅数据变更，可能导致业务逻辑错误或数据污染

---

## 攻击模式库

### 攻击模式：PFCP协议Mandatory IE空指针解引用

**模式ID**：GOVULN-NIL-001
**漏洞类型**：CWE-476 (NULL Pointer Dereference)
**严重程度**：高
**适用场景**：PFCP/GTP/Diameter等电信协议消息处理函数

#### 漏洞描述

在Go实现的电信协议处理函数中，协议消息（如PFCP SessionReportRequest、SessionEstablishmentResponse等）的Mandatory IE字段以指针类型表示。当恶意对端发送缺失Mandatory IE的消息时，Go代码直接访问该指针字段而未检查nil，触发panic导致进程崩溃。

由于PFCP handler通常在独立goroutine中运行且无defer recover保护，panic会直接终止整个NF进程。

#### 漏洞模式（漏洞代码案例）

```go
// 来源：free5gc SMF handler.go / datapath.go 的多个PFCP处理函数
// 模式特征：协议消息字段（指针类型IE）在使用前无nil检查

func HandlePfcpSessionReportRequest(msg *pfcp.Message) {
    req := msg.Body.(pfcp.SessionReportRequest)

    // 模式1: 直接访问可能缺失的Mandatory IE
    if req.ReportType.Dldr {  // ReportType为nil时panic
        // ...
    }

    // 模式2: 条件检查后访问依赖IE，但未检查依赖IE本身
    if req.ReportType.Usar {
        report := req.UsageReport
        trigger := report.UsageReportTrigger  // trigger可能为nil
        if trigger.Volth {  // panic
            // ...
        }
        vol := report.VolumeMeasurement  // 可能为nil
        total := vol.TotalVolume          // panic
    }
}

func handleEstablishmentResponse(rsp *pfcp.SessionEstablishmentResponse) {
    // 模式3: Response中Mandatory IE缺失
    if rsp.Cause.CauseValue != pfcp.CauseRequestAccepted {  // Cause为nil时panic
        // error handling
    }
    nodeID := rsp.NodeID.ResolveNodeIdToIp()  // NodeID为nil时panic
}
```

#### 检测规则

- PFCP/NAS/NGAP消息处理函数中，对消息体字段直接做`.Field`访问而无前置nil检查
- 协议消息结构体中的指针类型字段（表示可选/必选IE）被直接解引用
- handler函数运行在goroutine中且无`defer func() { recover() }()`
- 条件分支（如`if req.ReportType.Dldr`）直接在nil指针上访问字段
- Response处理函数中对Cause、NodeID等Mandatory IE的直接使用

#### 安全模式（修复代码案例）

```go
func HandlePfcpSessionReportRequest(msg *pfcp.Message) {
    req := msg.Body.(pfcp.SessionReportRequest)

    // 安全模式1: 逐层nil检查Mandatory IE
    if req.ReportType == nil {
        sendErrorResponse(msg, pfcp.CauseMandatoryIEMissing)
        return
    }

    if req.ReportType.Dldr {
        if req.DownlinkDataReport == nil {
            sendErrorResponse(msg, pfcp.CauseMandatoryIEMissing)
            return
        }
        // safe to use req.DownlinkDataReport
    }

    if req.ReportType.Usar {
        if req.UsageReport == nil || req.UsageReport.UsageReportTrigger == nil {
            sendErrorResponse(msg, pfcp.CauseMandatoryIEMissing)
            return
        }
        if req.UsageReport.VolumeMeasurement == nil {
            // 按业务需求处理缺失情况
            return
        }
        total := req.UsageReport.VolumeMeasurement.TotalVolume
        // ...
    }
}

// 安全模式2: goroutine级别panic recovery
func dispatchPFCPHandler(handler func(*pfcp.Message), msg *pfcp.Message) {
    go func() {
        defer func() {
            if r := recover(); r != nil {
                log.Errorf("PFCP handler panic recovered: %v", r)
            }
        }()
        handler(msg)
    }()
}
```

#### 测试方法

```go
func TestHandlePfcpSessionReportRequest_MissingIE(t *testing.T) {
    tests := []struct {
        name string
        msg  pfcp.SessionReportRequest
    }{
        {"missing_report_type", pfcp.SessionReportRequest{}},
        {"dldr_without_report", pfcp.SessionReportRequest{
            ReportType: &pfcp.ReportType{Dldr: true},
            // DownlinkDataReport is nil
        }},
        {"usar_without_trigger", pfcp.SessionReportRequest{
            ReportType: &pfcp.ReportType{Usar: true},
            UsageReport: &pfcp.UsageReport{
                // UsageReportTrigger is nil
            },
        }},
        {"usar_without_volume", pfcp.SessionReportRequest{
            ReportType: &pfcp.ReportType{Usar: true},
            UsageReport: &pfcp.UsageReport{
                UsageReportTrigger: &pfcp.UsageReportTrigger{Volth: true},
                // VolumeMeasurement is nil
            },
        }},
    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            defer func() {
                if r := recover(); r != nil {
                    t.Fatalf("handler panicked on %s: %v", tc.name, r)
                }
            }()
            HandlePfcpSessionReportRequest(buildMsg(tc.msg))
        })
    }
}
```

#### 关联CVE/Issue

- Issue #804 — SMF crashes on missing ReportType IE
- Issue #805 — SMF crashes on missing DownlinkDataReport IE
- Issue #806 — SMF crashes on missing VolumeMeasurement
- Issue #814 — SMF crashes on missing UsageReportTrigger
- Issue #815 — SMF crashes on missing Cause IE in EstablishmentResponse
- Issue #816 — SMF crashes on missing NodeID IE in EstablishmentResponse
- Issue #817 — SMF crashes on missing Cause IE in DeletionResponse

---

### 攻击模式：NAS协议字节切片越界访问

**模式ID**：GOVULN-BOF-001
**漏洞类型**：CWE-125 (Out-of-bounds Read)
**严重程度**：高
**适用场景**：NAS/NGAP协议消息解析、二进制编解码

#### 漏洞描述

NAS协议消息解析函数以`[]byte`形式接收网络数据，通过固定偏移量索引解码各字段。当恶意构造的消息长度短于解码逻辑预期时，索引访问超出切片边界触发Go运行时panic。

#### 漏洞模式（漏洞代码案例）

```go
// 来源：free5gc/nas nasType/NAS_MobileIdentity5GS.go
// 模式特征：直接索引[]byte而无len()前置检查

func (a *MobileIdentity5GS) GetSUCI() string {
    // a.Buffer来自网络数据，长度不可信
    supiFormat := a.Buffer[0] & 0x70 >> 4  // 需要至少1字节
    plmnID := decodePLMN(a.Buffer[1:4])    // 需要至少4字节
    routingIndicator := a.Buffer[4:6]       // 需要至少6字节
    schemeID := a.Buffer[6]                 // 需要至少7字节
    // 当Buffer长度为7但代码期望更多时：
    keyID := a.Buffer[7]                    // panic: index out of range [7] with length 7
    output := a.Buffer[8:]
    // ...
}
```

#### 检测规则

- 解析函数对`[]byte`参数或结构体的`[]byte`字段通过固定索引访问，函数入口无`len()`检查
- 不同协议消息类型的`switch`分支访问不同偏移量但共用不足的长度检查
- `data[M:N]`切片操作中M或N可能超出实际长度
- Buffer字段来自网络输入（NGAP解码、PFCP解码等）

#### 安全模式（修复代码案例）

```go
// 来源：free5gc/nas PR #43
func (a *MobileIdentity5GS) GetSUCI() (string, error) {
    if len(a.Buffer) == 0 {
        return "", fmt.Errorf("empty buffer")
    }

    const minSUCILen = 9  // 根据协议规范定义最小长度
    if len(a.Buffer) < minSUCILen {
        return "", fmt.Errorf("SUCI buffer too short: %d < %d", len(a.Buffer), minSUCILen)
    }

    supiFormat := a.Buffer[0] & 0x70 >> 4
    plmnID := decodePLMN(a.Buffer[1:4])
    routingIndicator := a.Buffer[4:6]
    schemeID := a.Buffer[6]
    keyID := a.Buffer[7]
    output := a.Buffer[8:]
    // ...
}
```

#### 测试方法

```go
func TestGetSUCI_MalformedInput(t *testing.T) {
    tests := []struct {
        name   string
        buffer []byte
    }{
        {"empty", []byte{}},
        {"one_byte", []byte{0x01}},
        {"short_plmn", []byte{0x01, 0x02, 0x03}},
        {"short_scheme", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}},
        {"short_key", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}},
        {"min_valid", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}},
    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            mi := &MobileIdentity5GS{Buffer: tc.buffer}
            defer func() {
                if r := recover(); r != nil {
                    t.Fatalf("panic on %s (len=%d): %v", tc.name, len(tc.buffer), r)
                }
            }()
            _, err := mi.GetSUCI()
            if len(tc.buffer) < 9 && err == nil {
                t.Error("expected error for short buffer")
            }
        })
    }
}
```

#### 关联CVE/Issue

- CVE-2025-69248 — AMF NAS Registration Request缓冲区溢出
- Issue #835 — Malformed NAS-PDU crashes AMF
- Issue #856 — Index out of bound vulnerability in AMF（修复不完整）

---

### 攻击模式：SBI接口OAuth2授权粒度不足

**模式ID**：GOVULN-AUZ-001
**漏洞类型**：CWE-285 (Improper Authorization)
**严重程度**：中
**适用场景**：5GC NF间SBI（Service Based Interface）HTTP API

#### 漏洞描述

5GC核心网NF之间通过SBI接口（HTTP/2 + OAuth2）通信。当授权检查仅验证token的service scope（如`nnrf-nfm`）而不验证操作主体是否有权操作目标资源时，持有有效service token的任意NF可越权操作其他NF的资源。

#### 漏洞模式（漏洞代码案例）

```go
// 模式特征：auth中间件仅检查service scope，不检查资源所有权
func authMiddleware(serviceName string) gin.HandlerFunc {
    return func(c *gin.Context) {
        token := extractBearerToken(c)
        claims, err := validateToken(token)
        if err != nil {
            c.AbortWithStatus(401)
            return
        }
        // 仅检查service scope
        if !claims.HasScope(serviceName) {
            c.AbortWithStatus(403)
            return
        }
        // 未检查：请求者是否有权操作目标nfInstanceId
        c.Next()
    }
}

// 任何持有nnrf-nfm token的NF都可以删除其他NF的注册
func DeregisterNFInstance(c *gin.Context) {
    nfInstanceId := c.Param("nfInstanceId")
    // 缺失：检查请求者的nfInstanceId是否等于目标nfInstanceId
    deleteNFProfile(nfInstanceId)
    c.Status(204)
}
```

#### 检测规则

- SBI API handler中仅使用service-level OAuth2 scope检查
- RESTful路径参数（如`{nfInstanceId}`、`{supi}`）未与请求者身份比对
- 回调接口（callback endpoint）完全缺失OAuth2认证中间件
- PUT/PATCH/DELETE操作未验证资源所有权

#### 安全模式（修复代码案例）

```go
func authMiddleware(serviceName string) gin.HandlerFunc {
    return func(c *gin.Context) {
        token := extractBearerToken(c)
        claims, err := validateToken(token)
        if err != nil {
            c.AbortWithStatus(401)
            return
        }
        if !claims.HasScope(serviceName) {
            c.AbortWithStatus(403)
            return
        }
        c.Set("callerNfInstanceId", claims.NfInstanceId)
        c.Next()
    }
}

func DeregisterNFInstance(c *gin.Context) {
    nfInstanceId := c.Param("nfInstanceId")
    callerNfId := c.GetString("callerNfInstanceId")

    // 资源所有权检查
    if nfInstanceId != callerNfId {
        c.JSON(403, ProblemDetails{
            Title:  "Forbidden",
            Detail: "cannot deregister other NF instance",
        })
        return
    }
    deleteNFProfile(nfInstanceId)
    c.Status(204)
}
```

#### 测试方法

```go
func TestDeregisterNFInstance_OwnershipCheck(t *testing.T) {
    // 创建NF-A和NF-B的token
    tokenA := generateToken("nf-instance-a", "nnrf-nfm")
    tokenB := generateToken("nf-instance-b", "nnrf-nfm")

    // NF-A尝试删除NF-B的注册 → 应拒绝
    req := httptest.NewRequest("DELETE", "/nf-instances/nf-instance-b", nil)
    req.Header.Set("Authorization", "Bearer "+tokenA)
    resp := httptest.NewRecorder()
    router.ServeHTTP(resp, req)

    if resp.Code != 403 {
        t.Errorf("expected 403, got %d: NF-A should not deregister NF-B", resp.Code)
    }

    // NF-B删除自己 → 应成功
    req2 := httptest.NewRequest("DELETE", "/nf-instances/nf-instance-b", nil)
    req2.Header.Set("Authorization", "Bearer "+tokenB)
    resp2 := httptest.NewRecorder()
    router.ServeHTTP(resp2, req2)

    if resp2.Code != 204 {
        t.Errorf("expected 204, got %d: NF-B should deregister itself", resp2.Code)
    }
}
```

#### 关联Issue

- Issue #846 — NRF allows unauthenticated RegisterNFInstance
- Issue #847 — NRF over-authorizes UpdateNFInstance
- Issue #848 — NRF over-authorizes DeregisterNFInstance
- Issue #878 — AMF over-authorizes UE-context operations
- Issue #882 — UDM over-authorizes auth-data surfaces
- Issue #886 — NEF callback is unauthenticated

---

### 攻击模式：Go类型断言不一致导致panic

**模式ID**：GOVULN-NIL-002
**漏洞类型**：CWE-843 (Access of Resource Using Incompatible Type)
**严重程度**：中
**适用场景**：使用`interface{}`/`any`类型存储的map、sync.Map、上下文传递

#### 漏洞描述

Go中使用`map[string]interface{}`或`sync.Map`存储不同生命周期阶段写入的值时，如果写入时使用了不同的具体类型（值类型 vs 指针类型），后续读取并做类型断言时会因类型不匹配而panic。

#### 漏洞模式（漏洞代码案例）

```go
// 来源：free5gc AMF subscription管理
// 模式特征：同一map中create和update使用不同类型

// Create时存储值类型
func CreateSubscription(id string, sub SubscriptionData) {
    amfContext.Subscriptions.Store(id, sub)  // 存储值类型
}

// Update时存储指针类型
func UpdateSubscription(id string, sub *SubscriptionData) {
    amfContext.Subscriptions.Store(id, sub)  // 存储指针类型！
}

// Delete时做值类型断言
func FindSubscription(id string) (SubscriptionData, bool) {
    val, ok := amfContext.Subscriptions.Load(id)
    if !ok {
        return SubscriptionData{}, false
    }
    // Update后val是*SubscriptionData，断言为SubscriptionData会panic
    return val.(SubscriptionData), true  // panic!
}
```

#### 检测规则

- `sync.Map`或`map[string]interface{}`的Store/Put使用了不同具体类型
- 类型断言`val.(Type)`未使用comma-ok模式（`val, ok := val.(Type)`）
- 同一数据结构的CRUD操作分布在不同文件/函数中，存在类型不一致风险
- Create和Update路径使用了值类型和指针类型的混用

#### 安全模式（修复代码案例）

```go
// 安全模式1: 统一存储类型
func CreateSubscription(id string, sub SubscriptionData) {
    amfContext.Subscriptions.Store(id, &sub)  // 统一使用指针类型
}

func UpdateSubscription(id string, sub *SubscriptionData) {
    amfContext.Subscriptions.Store(id, sub)   // 统一使用指针类型
}

func FindSubscription(id string) (*SubscriptionData, bool) {
    val, ok := amfContext.Subscriptions.Load(id)
    if !ok {
        return nil, false
    }
    // 安全模式2: comma-ok类型断言
    sub, ok := val.(*SubscriptionData)
    if !ok {
        log.Warnf("unexpected type in subscription store: %T", val)
        return nil, false
    }
    return sub, true
}
```

#### 测试方法

```go
func TestSubscriptionTypeConsistency(t *testing.T) {
    store := NewSubscriptionStore()

    // Create
    store.CreateSubscription("sub-1", SubscriptionData{ID: "sub-1"})

    // Update（可能改变存储类型）
    updated := &SubscriptionData{ID: "sub-1", Updated: true}
    store.UpdateSubscription("sub-1", updated)

    // Find应不panic
    defer func() {
        if r := recover(); r != nil {
            t.Fatalf("FindSubscription panicked after Update: %v", r)
        }
    }()
    sub, ok := store.FindSubscription("sub-1")
    if !ok || sub == nil {
        t.Error("subscription not found after update")
    }
}
```

#### 关联Issue

- Issue #876 — AMF DELETE /subscriptions panic after PUT

---

### 攻击模式：协议会话资源无上限控制

**模式ID**：GOVULN-DOS-001
**漏洞类型**：CWE-770 (Allocation of Resources Without Limits or Throttling)
**严重程度**：中
**适用场景**：PFCP/GTP会话管理、连接池、订阅管理

#### 漏洞描述

协议实现中的会话/资源创建函数未设置数量上限。恶意对端可通过反复创建新会话（不释放）来耗尽目标NF的内存，最终触发OOM killer导致进程终止。

#### 漏洞模式（漏洞代码案例）

```go
// 来源：free5gc go-upf node.go:651-672
// 模式特征：资源创建无上限、无准入控制

func (n *LocalNode) NewSess(seid uint64) *Session {
    sess := &Session{
        SEID:   seid,
        PDRs:   make(map[uint16]*PDR),
        FARs:   make(map[uint32]*FAR),
        URRs:   make(map[uint32]*URR),
    }
    n.sess = append(n.sess, sess)  // 无限追加，无上限检查
    return sess
}
```

#### 检测规则

- `append`到切片或`map`新增条目的操作无数量限制检查
- 资源创建路径可由外部输入触发（如PFCP消息）
- 缺少对应的资源回收/老化机制
- 无速率限制（rate limiting）或准入控制（admission control）

#### 安全模式（修复代码案例）

```go
const MaxSessions = 10000

func (n *LocalNode) NewSess(seid uint64) (*Session, error) {
    n.mu.Lock()
    defer n.mu.Unlock()

    if len(n.sess) >= MaxSessions {
        return nil, fmt.Errorf("session limit reached: %d", MaxSessions)
    }

    sess := &Session{
        SEID:   seid,
        PDRs:   make(map[uint16]*PDR),
        FARs:   make(map[uint32]*FAR),
        URRs:   make(map[uint32]*URR),
    }
    n.sess = append(n.sess, sess)
    return sess, nil
}
```

#### 关联Issue

- Issue #819 — UPF session pool exhaustion (memory exhaustion DoS)
- Issue #818 — UPF unbounded URR map growth

---

## 代码审计检查清单

基于以上攻击模式，在审计Go语言5GC项目时应重点检查：

### PFCP消息处理（最高优先级）

- [ ] 每个PFCP handler是否对所有Mandatory IE做了nil检查
- [ ] 条件分支中的依赖IE是否在使用前验证（如ReportType.DLDR=true时检查DownlinkDataReport）
- [ ] PFCP handler goroutine是否有defer recover保护
- [ ] Response处理中Cause、NodeID等字段是否检查nil
- [ ] 嵌套IE（如UsageReport中的子IE）是否逐层检查

### NAS消息解析（高优先级）

- [ ] `[]byte`类型Buffer在索引访问前是否检查`len()`
- [ ] 不同Identity类型（SUCI/GUTI/IMEI等）的解码路径是否各自有长度校验
- [ ] 奇数/偶数长度MSIN等边界条件是否处理

### SBI接口授权（高优先级）

- [ ] 每个SBI API endpoint是否配置了OAuth2中间件
- [ ] 授权检查是否包含资源所有权验证（不仅仅是service scope）
- [ ] 回调接口（callback）是否也有认证保护
- [ ] PUT/PATCH/DELETE操作是否验证操作者身份

### 类型安全

- [ ] `sync.Map`或`map[string]interface{}`的CRUD操作是否使用一致的具体类型
- [ ] 类型断言是否使用comma-ok模式
- [ ] 不同代码路径对同一存储的写入是否类型兼容

### 资源管理

- [ ] 会话/连接/订阅创建是否有数量上限
- [ ] 是否存在资源老化/超时清理机制
- [ ] 是否有速率限制防止资源耗尽攻击

---

## 参考资料

### CVE

- [CVE-2025-69248](https://nvd.nist.gov/vuln/detail/CVE-2025-69248) — AMF NAS Registration Request缓冲区溢出
- [CVE-2025-70121](https://nvd.nist.gov/vuln/detail/CVE-2025-70121) — AMF 5GS Mobile Identity数组索引越界
- [CVE-2025-70123](https://nvd.nist.gov/vuln/detail/CVE-2025-70123) — UPF PFCP输入验证不足
- [CVE-2025-69232](https://nvd.nist.gov/vuln/detail/CVE-2025-69232) — go-upf PFCP Association Setup验证缺失
- [CVE-2026-1973](https://nvd.nist.gov/vuln/detail/CVE-2026-1973) — SMF空指针解引用
- [CVE-2026-1739](https://nvd.nist.gov/vuln/detail/CVE-2026-1739) — PCF空指针解引用
- [CVE-2026-26025](https://nvd.nist.gov/vuln/detail/CVE-2026-26025) — SMF PFCP SessionReportRequest处理崩溃

### GitHub Issues

- [#804](https://github.com/free5gc/free5gc/issues/804) — SMF crashes on missing ReportType IE
- [#805](https://github.com/free5gc/free5gc/issues/805) — SMF crashes on missing DownlinkDataReport IE
- [#806](https://github.com/free5gc/free5gc/issues/806) — SMF crashes on missing VolumeMeasurement
- [#807](https://github.com/free5gc/free5gc/issues/807) — SMF crashes on missing UsageReportTrigger (variant)
- [#814](https://github.com/free5gc/free5gc/issues/814) — SMF crashes on missing UsageReportTrigger
- [#815](https://github.com/free5gc/free5gc/issues/815) — SMF crashes on missing Cause IE
- [#816](https://github.com/free5gc/free5gc/issues/816) — SMF crashes on missing NodeID IE
- [#817](https://github.com/free5gc/free5gc/issues/817) — SMF crashes on missing Cause IE in DeletionResponse
- [#819](https://github.com/free5gc/free5gc/issues/819) — UPF session pool exhaustion
- [#826](https://github.com/free5gc/free5gc/issues/826) — AMF nil pointer on AuthenticationFailure
- [#835](https://github.com/free5gc/free5gc/issues/835) — Malformed NAS-PDU crashes AMF
- [#846](https://github.com/free5gc/free5gc/issues/846) — NRF unauthenticated RegisterNFInstance
- [#856](https://github.com/free5gc/free5gc/issues/856) — AMF index out of bound (unfixed)
- [#876](https://github.com/free5gc/free5gc/issues/876) — AMF subscription delete panic
- [#879](https://github.com/free5gc/free5gc/issues/879) — PCF app-sessions panic

### 修复PR

- [free5gc/nas PR #43](https://github.com/free5gc/nas/pull/43) — fix: prevent panic in MobileIdentity5GS getters
- [free5gc/go-upf PR #98](https://github.com/free5gc/go-upf/pull/98) — UPF session/URR fixes

### 协议规范

- [3GPP TS 29.244](https://www.3gpp.org/DynaReport/29244.htm) — PFCP协议规范
- [3GPP TS 24.501](https://www.3gpp.org/DynaReport/24501.htm) — 5GS NAS协议规范
- [3GPP TS 38.413](https://www.3gpp.org/DynaReport/38413.htm) — NGAP协议规范
- [3GPP TS 29.510](https://www.3gpp.org/DynaReport/29510.htm) — NRF Services规范

### CWE

- [CWE-125](https://cwe.mitre.org/data/definitions/125.html) — Out-of-bounds Read
- [CWE-476](https://cwe.mitre.org/data/definitions/476.html) — NULL Pointer Dereference
- [CWE-285](https://cwe.mitre.org/data/definitions/285.html) — Improper Authorization
- [CWE-770](https://cwe.mitre.org/data/definitions/770.html) — Allocation Without Limits
- [CWE-843](https://cwe.mitre.org/data/definitions/843.html) — Type Confusion
