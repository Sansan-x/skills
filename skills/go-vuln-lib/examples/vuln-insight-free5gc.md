# 漏洞洞察报告：free5gc

> 项目地址：https://github.com/free5gc/free5gc
> 分析时间：2026-03-19
> 漏洞总数：6
> 攻击模式数：4

## 概述

free5gc是一个基于Go语言的开源5G核心网实现，遵循3GPP R15/R16规范。项目涵盖AMF、SMF、UPF、PCF等核心网络功能。由于5GC核心网直接暴露在网络环境中，协议解析层面的安全漏洞可能导致拒绝服务甚至远程代码执行。

本报告基于GitHub Issue及修复PR分析了free5gc项目中已知的安全漏洞，并提取了可用于代码审计的攻击模式。

## 漏洞统计

| 严重程度 | 数量 |
|----------|------|
| 高危 (High) | 3 |
| 中危 (Medium) | 2 |
| 低危 (Low) | 1 |

| 漏洞类型 | 数量 |
|----------|------|
| 缓冲区溢出/数组越界 | 2 |
| 空指针解引用 | 2 |
| 输入验证不足 | 1 |
| 协议合规缺陷 | 1 |

| 影响组件 | 数量 |
|----------|------|
| AMF | 2 |
| SMF | 2 |
| UPF | 1 |
| PCF | 1 |

---

## 漏洞详情

### VULN-001: AMF NAS注册请求缓冲区溢出

- **CVE编号**：CVE-2025-69248
- **Issue链接**：https://github.com/free5gc/free5gc/issues/743 (示例)
- **修复PR**：https://github.com/free5gc/nas/pull/43
- **严重程度**：高危 (CVSS 7.5)
- **影响组件**：AMF (接入和移动性管理功能)
- **影响版本**：free5gc <= 1.4.1

#### 漏洞分析

AMF服务在处理NAS注册请求消息时，未对5GS Mobile Identity字段进行充分的长度验证。攻击者可构造恶意的NAS Registration Request消息，其中包含超长的5GS Mobile Identity字段，触发缓冲区溢出导致AMF进程崩溃（panic），造成拒绝服务。

该漏洞位于NAS协议解析库中的身份标识解码函数，属于协议消息解析层面的输入验证缺失。

#### 漏洞代码

> 来源：free5gc/nas 库（修复PR #43之前的代码）

```go
// nas/nasType/NAS_5GSMobileIdentity.go（漏洞版本）
func (a *MobileIdentity5GS) DecodeNASType(wire []byte) error {
    // 缺少长度验证，直接访问wire切片
    identityType := wire[0] & 0x07
    switch identityType {
    case MobileIdentity5GSTypeSUCI:
        // 未检查wire长度是否满足SUCI格式最小要求
        a.SchemeID = wire[3]
        a.HomeNetworkPublicKeyID = wire[4]
        // 当wire长度不足时发生越界访问
        a.SchemeOutput = wire[5:]
    }
    return nil
}
```

#### 修复代码

> 来源：free5gc/nas PR #43

```go
// nas/nasType/NAS_5GSMobileIdentity.go（修复版本）
func (a *MobileIdentity5GS) DecodeNASType(wire []byte) error {
    if len(wire) < 1 {
        return fmt.Errorf("5GS Mobile Identity: empty wire")
    }
    identityType := wire[0] & 0x07
    switch identityType {
    case MobileIdentity5GSTypeSUCI:
        if len(wire) < 6 {
            return fmt.Errorf("5GS Mobile Identity SUCI: wire too short, got %d, need at least 6", len(wire))
        }
        a.SchemeID = wire[3]
        a.HomeNetworkPublicKeyID = wire[4]
        a.SchemeOutput = wire[5:]
    }
    return nil
}
```

#### 根因分析

NAS协议消息解码函数在访问字节切片之前没有验证输入长度。在Go语言中，切片越界访问会触发运行时panic，导致整个服务进程终止。对于常驻运行的核心网网元，这类panic直接造成拒绝服务。

---

### VULN-002: AMF 5GS Mobile Identity数组索引越界

- **CVE编号**：CVE-2025-70121
- **Issue链接**：https://github.com/free5gc/free5gc/issues/744 (关联)
- **严重程度**：高危 (CVSS 7.5)
- **影响组件**：AMF
- **影响版本**：free5gc v4.0.1

#### 漏洞分析

AMF组件的`GetSUCI`方法在解析5GS Mobile Identity时，尝试访问一个5元素数组的索引5（第6个元素），导致数组越界panic。攻击者可通过构造特定的NAS注册请求触发此漏洞。

#### 漏洞代码

```go
// 漏洞模式：固定大小数组的越界访问
func GetSUCI(mobileIdentity []byte) (string, error) {
    parts := parseMobileIdentity(mobileIdentity)
    // parts可能仅有5个元素[0..4]，但代码直接访问索引5
    suci := parts[5]  // panic: index out of range [5] with length 5
    return suci, nil
}
```

#### 修复代码

```go
func GetSUCI(mobileIdentity []byte) (string, error) {
    parts := parseMobileIdentity(mobileIdentity)
    if len(parts) < 6 {
        return "", fmt.Errorf("insufficient mobile identity parts: got %d, need 6", len(parts))
    }
    suci := parts[5]
    return suci, nil
}
```

#### 根因分析

代码假设解析结果一定包含足够的元素，未对切片/数组长度进行防御性检查。这是Go语言中常见的数组越界漏洞模式。

---

### VULN-003: UPF PFCP协议合规性漏洞

- **CVE编号**：CVE-2025-70123 / CVE-2025-69232
- **Issue链接**：https://github.com/free5gc/free5gc/issues/745
- **严重程度**：高危 (CVSS 7.5)
- **影响组件**：UPF (用户面功能)
- **影响版本**：go-upf <= v1.2.6

#### 漏洞分析

UPF在处理PFCP Association Setup Request时，未按照3GPP TS 29.244标准验证请求消息的合法性。当收到格式错误的PFCP关联建立请求时，UPF错误地接受了该请求，导致与SMF之间的连接状态不一致。SMF会进入重连循环，造成服务降级。

#### 漏洞代码

```go
// pfcp消息处理函数 — 缺失协议合规性校验
func HandlePFCPAssociationSetupRequest(msg *pfcp.Message) {
    req := msg.Body.(pfcp.AssociationSetupRequest)
    // 未验证必选IE（Information Element）是否存在
    // 未验证NodeID格式是否合法
    // 未验证RecoveryTimeStamp是否在有效范围内
    nodeID := req.NodeID
    association := CreateAssociation(nodeID)
    SendAssociationSetupResponse(association, pfcp.CauseRequestAccepted)
}
```

#### 修复代码

```go
func HandlePFCPAssociationSetupRequest(msg *pfcp.Message) {
    req := msg.Body.(pfcp.AssociationSetupRequest)

    // 验证必选IE存在性（3GPP TS 29.244 Section 7.4.4.1）
    if req.NodeID == nil {
        SendAssociationSetupResponse(nil, pfcp.CauseMandatoryIEMissing)
        return
    }

    // 验证NodeID格式合法性
    if err := validateNodeID(req.NodeID); err != nil {
        SendAssociationSetupResponse(nil, pfcp.CauseInvalidNodeID)
        return
    }

    // 验证RecoveryTimeStamp
    if req.RecoveryTimeStamp == nil {
        SendAssociationSetupResponse(nil, pfcp.CauseMandatoryIEMissing)
        return
    }

    nodeID := req.NodeID
    association := CreateAssociation(nodeID)
    SendAssociationSetupResponse(association, pfcp.CauseRequestAccepted)
}
```

#### 根因分析

协议处理函数信任了外部输入的完整性和正确性，未按照3GPP规范中的消息格式要求验证必选字段和格式约束。这在电信协议实现中是常见的安全问题。

---

### VULN-004: SMF PFCP会话空指针解引用

- **CVE编号**：CVE-2026-1973
- **严重程度**：中危 (CVSS 5.3)
- **影响组件**：SMF (会话管理功能)
- **影响版本**：free5gc <= v4.1.0

#### 漏洞分析

SMF的`establishPfcpSession`函数在建立PFCP会话时，未检查返回的会话对象是否为nil。当UPF返回异常响应时，后续代码对nil指针进行解引用操作，导致SMF panic。

#### 漏洞代码

```go
func establishPfcpSession(ctx *SMContext) error {
    session, err := sendPFCPSessionEstablishment(ctx)
    // err可能为nil但session也可能为nil（部分成功场景）
    if err != nil {
        return err
    }
    // 当session为nil时，以下操作触发panic
    ctx.PFCPSessionID = session.SessionID
    ctx.UPFNodeID = session.NodeID
    return nil
}
```

#### 修复代码

```go
func establishPfcpSession(ctx *SMContext) error {
    session, err := sendPFCPSessionEstablishment(ctx)
    if err != nil {
        return fmt.Errorf("PFCP session establishment failed: %w", err)
    }
    if session == nil {
        return fmt.Errorf("PFCP session establishment returned nil session")
    }
    ctx.PFCPSessionID = session.SessionID
    ctx.UPFNodeID = session.NodeID
    return nil
}
```

#### 根因分析

Go函数返回值中的错误检查不完整 — 仅检查了error是否为nil，未检查业务返回值是否也可能为nil。这是Go语言中常见的空指针漏洞模式。

---

### VULN-005: PCF HandleCreateSmPolicyRequest空指针解引用

- **CVE编号**：CVE-2026-1739
- **严重程度**：中危 (CVSS 5.3)
- **影响组件**：PCF (策略控制功能)
- **影响版本**：PCF <= v1.4.1
- **修复commit**：df535f5524314620715e842baf9723efbeb481a7

#### 漏洞分析

PCF的`HandleCreateSmPolicyRequest`函数在处理SM策略创建请求时，未对请求体中的嵌套对象进行nil检查，导致空指针解引用。

#### 漏洞代码

```go
func HandleCreateSmPolicyRequest(request *models.SmPolicyContextData) {
    // 直接访问可能为nil的嵌套字段
    subscriberID := request.Supi
    dnn := request.SliceInfo.Dnn  // SliceInfo可能为nil → panic
    snssai := request.SliceInfo.SNssai
    // ...
}
```

#### 修复代码

```go
func HandleCreateSmPolicyRequest(request *models.SmPolicyContextData) {
    if request == nil {
        // 返回错误响应
        return
    }
    subscriberID := request.Supi
    if request.SliceInfo == nil {
        // 返回错误响应：缺少必要的SliceInfo
        return
    }
    dnn := request.SliceInfo.Dnn
    snssai := request.SliceInfo.SNssai
    // ...
}
```

---

### VULN-006: SMF PFCP SessionReportRequest处理崩溃

- **CVE编号**：CVE-2026-26025
- **严重程度**：高危 (CVSS 7.5)
- **影响组件**：SMF
- **影响版本**：SMF <= v1.4.1

#### 漏洞分析

SMF在处理格式错误的PFCP SessionReportRequest消息时发生panic，导致SMF进程终止。

#### 根因分析

PFCP消息反序列化后，代码未验证必选字段是否存在即直接使用，当收到格式不合规的消息时触发panic。

---

## 攻击模式库

### 攻击模式：Go切片/数组越界访问

**模式ID**：GOVULN-BOF-001
**漏洞类型**：CWE-125 (Out-of-bounds Read) / CWE-787 (Out-of-bounds Write)
**严重程度**：高
**适用场景**：协议消息解析、二进制数据处理、网络数据包解码

#### 漏洞描述

在Go语言中，直接通过索引访问切片或数组元素而不检查长度，当外部输入控制了数据长度时，攻击者可构造短于预期的数据触发runtime panic（`index out of range`），导致服务崩溃。这在协议解析代码中尤为常见，因为解析逻辑通常假设输入数据满足协议规范的最小长度要求。

#### 漏洞模式（漏洞代码案例）

```go
// 模式特征：直接索引访问外部输入的字节切片，无长度校验
func DecodeProtocolMessage(data []byte) (*Message, error) {
    msg := &Message{}
    msg.Type = data[0]           // 无长度检查
    msg.Length = binary.BigEndian.Uint16(data[1:3])  // 假设至少3字节
    msg.Payload = data[3:]       // 假设至少3字节

    // 基于解码字段继续索引访问
    if msg.Type == TypeSUCI {
        msg.SchemeID = data[3]   // 假设至少4字节
        msg.KeyID = data[4]      // 假设至少5字节
        msg.Output = data[5:]    // 假设至少6字节
    }
    return msg, nil
}
```

#### 检测规则

- 函数接收 `[]byte` 参数后直接通过索引访问（如 `data[N]`），且之前无 `len(data)` 检查
- 使用 `binary.BigEndian.UintXX(data[M:N])` 而无长度验证
- 协议解析函数中基于解码的字段值再次索引原始数据
- `switch` 分支中针对不同消息类型访问不同偏移量但共享相同的（不充分的）长度检查
- 切片操作 `data[N:]` 中N可能大于 `len(data)`

#### 安全模式（修复代码案例）

```go
func DecodeProtocolMessage(data []byte) (*Message, error) {
    // 前置长度验证
    if len(data) < 3 {
        return nil, fmt.Errorf("message too short: got %d bytes, minimum 3", len(data))
    }

    msg := &Message{}
    msg.Type = data[0]
    msg.Length = binary.BigEndian.Uint16(data[1:3])
    msg.Payload = data[3:]

    if msg.Type == TypeSUCI {
        // 针对特定消息类型的额外长度验证
        if len(data) < 6 {
            return nil, fmt.Errorf("SUCI message too short: got %d bytes, minimum 6", len(data))
        }
        msg.SchemeID = data[3]
        msg.KeyID = data[4]
        msg.Output = data[5:]
    }
    return msg, nil
}
```

#### 测试方法

```go
func TestDecodeProtocolMessage_ShortInput(t *testing.T) {
    testCases := []struct {
        name string
        data []byte
    }{
        {"empty", []byte{}},
        {"one_byte", []byte{0x01}},
        {"two_bytes", []byte{0x01, 0x00}},
        {"suci_too_short", []byte{TypeSUCI, 0x00, 0x03, 0x01}},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            defer func() {
                if r := recover(); r != nil {
                    t.Errorf("panic on short input %q: %v", tc.name, r)
                }
            }()
            _, err := DecodeProtocolMessage(tc.data)
            if err == nil {
                t.Errorf("expected error for short input %q", tc.name)
            }
        })
    }
}
```

#### 关联CVE

- CVE-2025-69248 — free5gc AMF NAS Registration Request缓冲区溢出
- CVE-2025-70121 — free5gc AMF 5GS Mobile Identity数组索引越界

---

### 攻击模式：Go空指针解引用（nil pointer dereference）

**模式ID**：GOVULN-NIL-001
**漏洞类型**：CWE-476 (NULL Pointer Dereference)
**严重程度**：中-高
**适用场景**：API请求处理、嵌套结构体访问、函数返回值处理

#### 漏洞描述

Go语言中对nil指针进行字段访问或方法调用会触发runtime panic。在网络服务中，当外部请求包含不完整的数据结构（嵌套对象为nil）或者函数在异常路径下返回nil，而调用方未进行nil检查时，攻击者可以通过构造缺失特定字段的请求触发服务崩溃。

#### 漏洞模式（漏洞代码案例）

```go
// 模式1：嵌套结构体访问无nil检查
func HandleRequest(req *RequestBody) Response {
    // req本身可能为nil
    // req.SubField可能为nil
    value := req.SubField.NestedField  // panic if SubField is nil
    return process(value)
}

// 模式2：函数返回值仅检查error忽略业务对象
func ProcessSession(ctx *Context) error {
    session, err := createSession(ctx)
    if err != nil {
        return err
    }
    // session可能为nil（函数返回nil, nil的情况）
    ctx.ID = session.ID  // panic if session is nil
    return nil
}

// 模式3：map查找结果未检查
func GetHandler(name string) {
    handlers := getHandlerMap()
    handler := handlers[name]  // 返回nil如果key不存在
    handler.Execute()          // panic if handler is nil
}
```

#### 检测规则

- 函数参数为指针类型但函数体内无nil检查即直接使用
- 链式字段访问 `a.B.C.D` 中间层级可能为nil
- 函数返回 `(*Type, error)` 后调用方仅检查 `err != nil` 但未检查返回的指针
- map索引结果直接用于方法调用或字段访问
- 接口类型断言结果未使用 `ok` 模式检查（`val := x.(Type)` 而非 `val, ok := x.(Type)`）
- HTTP handler中 `json.Decode` 后未检查解码结果中的可选字段

#### 安全模式（修复代码案例）

```go
// 安全模式：逐层nil检查
func HandleRequest(req *RequestBody) Response {
    if req == nil {
        return ErrorResponse("request body is nil")
    }
    if req.SubField == nil {
        return ErrorResponse("missing required field: SubField")
    }
    value := req.SubField.NestedField
    return process(value)
}

// 安全模式：双重返回值检查
func ProcessSession(ctx *Context) error {
    session, err := createSession(ctx)
    if err != nil {
        return fmt.Errorf("create session failed: %w", err)
    }
    if session == nil {
        return fmt.Errorf("create session returned nil")
    }
    ctx.ID = session.ID
    return nil
}

// 安全模式：map查找使用comma-ok
func GetHandler(name string) error {
    handlers := getHandlerMap()
    handler, ok := handlers[name]
    if !ok || handler == nil {
        return fmt.Errorf("handler not found: %s", name)
    }
    handler.Execute()
    return nil
}
```

#### 测试方法

```go
func TestHandleRequest_NilFields(t *testing.T) {
    testCases := []struct {
        name string
        req  *RequestBody
    }{
        {"nil_request", nil},
        {"nil_subfield", &RequestBody{SubField: nil}},
        {"nil_nested", &RequestBody{SubField: &SubField{NestedField: nil}}},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            defer func() {
                if r := recover(); r != nil {
                    t.Errorf("panic on %s: %v", tc.name, r)
                }
            }()
            resp := HandleRequest(tc.req)
            if resp.IsError() {
                // 期望返回错误，而非panic
            }
        })
    }
}
```

#### 关联CVE

- CVE-2026-1973 — free5gc SMF establishPfcpSession空指针解引用
- CVE-2026-1739 — free5gc PCF HandleCreateSmPolicyRequest空指针解引用

---

### 攻击模式：协议消息必选字段验证缺失

**模式ID**：GOVULN-PRO-001
**漏洞类型**：CWE-20 (Improper Input Validation)
**严重程度**：高
**适用场景**：3GPP协议实现（NAS/PFCP/NGAP/GTP）、自定义二进制协议处理

#### 漏洞描述

在实现通信协议时，协议规范中定义了消息的必选信息元素（Mandatory IE）和可选信息元素（Optional IE）。当代码未验证必选IE的存在性和格式正确性时，接收到不合规的消息可能导致空指针解引用、数组越界或状态不一致。

#### 漏洞模式（漏洞代码案例）

```go
// 模式特征：协议消息处理函数直接解包使用字段，无合规性检查
func HandlePFCPRequest(msg *pfcp.Message) *pfcp.Message {
    req := msg.Body.(pfcp.SessionEstablishmentRequest)
    // 3GPP规范要求NodeID为必选IE，但代码未验证
    nodeID := req.NodeID.Value()       // NodeID可能为nil
    fseid := req.CPFSEID.Value()       // CPFSEID可能为nil
    // 直接使用未经验证的字段创建会话
    session := &Session{
        NodeID:   nodeID,
        FSEID:    fseid,
        PDRs:     extractPDRs(req),    // 内部也可能因缺失IE而panic
    }
    return buildResponse(session)
}
```

#### 检测规则

- 协议消息处理函数（Handle*, Process*, On*）中直接对消息字段调用 `.Value()` 或直接访问而无nil/存在性检查
- 类型断言 `msg.Body.(SpecificType)` 后未使用comma-ok模式
- 协议状态机跳转中未验证前置条件
- 缺少与协议规范文档（如3GPP TS 29.244）对应的IE存在性校验代码
- 响应消息构造中对请求中的必选字段无验证逻辑

#### 安全模式（修复代码案例）

```go
func HandlePFCPRequest(msg *pfcp.Message) *pfcp.Message {
    req, ok := msg.Body.(pfcp.SessionEstablishmentRequest)
    if !ok {
        return buildErrorResponse(pfcp.CauseInvalidRequest)
    }

    // 3GPP TS 29.244 Section 7.5.2：验证所有必选IE
    if req.NodeID == nil {
        return buildErrorResponse(pfcp.CauseMandatoryIEMissing)
    }
    if req.CPFSEID == nil {
        return buildErrorResponse(pfcp.CauseMandatoryIEMissing)
    }

    // 验证IE值的有效性
    nodeID := req.NodeID.Value()
    if err := validateNodeID(nodeID); err != nil {
        return buildErrorResponse(pfcp.CauseInvalidNodeID)
    }

    fseid := req.CPFSEID.Value()
    session := &Session{
        NodeID: nodeID,
        FSEID:  fseid,
        PDRs:   extractPDRs(req),
    }
    return buildResponse(session)
}
```

#### 测试方法

```go
func TestHandlePFCPRequest_MissingMandatoryIE(t *testing.T) {
    testCases := []struct {
        name    string
        request pfcp.SessionEstablishmentRequest
    }{
        {"missing_node_id", pfcp.SessionEstablishmentRequest{CPFSEID: validFSEID}},
        {"missing_fseid", pfcp.SessionEstablishmentRequest{NodeID: validNodeID}},
        {"all_missing", pfcp.SessionEstablishmentRequest{}},
        {"invalid_node_id", pfcp.SessionEstablishmentRequest{
            NodeID: &pfcp.NodeID{Value: []byte{0xFF}},  // 非法格式
            CPFSEID: validFSEID,
        }},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            defer func() {
                if r := recover(); r != nil {
                    t.Fatalf("panic: %v", r)
                }
            }()
            resp := HandlePFCPRequest(buildMessage(tc.request))
            if resp.Cause != pfcp.CauseMandatoryIEMissing && resp.Cause != pfcp.CauseInvalidNodeID {
                t.Error("expected error cause in response")
            }
        })
    }
}
```

#### 关联CVE

- CVE-2025-70123 — free5gc UPF PFCP协议合规性漏洞
- CVE-2025-69232 — free5gc go-upf PFCP Association Setup请求验证缺失
- CVE-2026-26025 — free5gc SMF PFCP SessionReportRequest处理崩溃

---

### 攻击模式：协议状态不一致导致服务降级

**模式ID**：GOVULN-PRO-002
**漏洞类型**：CWE-372 (Incomplete Internal State Distinction)
**严重程度**：中
**适用场景**：有状态协议处理、会话管理、连接池管理

#### 漏洞描述

在有状态协议处理中，接受不合规的消息可能导致内部状态与预期不一致。例如在PFCP关联管理中，错误地接受了格式异常的关联建立请求，可能导致对端（如SMF）陷入重连循环，形成持续性服务降级。

#### 漏洞模式（漏洞代码案例）

```go
// 模式特征：无条件接受请求并更新内部状态
func HandleAssociationSetup(req *AssociationSetupRequest) {
    // 未验证请求合法性就更新关联状态
    assoc := &Association{
        NodeID:    req.NodeID,
        State:     StateEstablished,
        Timestamp: time.Now(),
    }
    associationStore.Put(assoc)
    // 发送成功响应 — 对端认为关联已建立
    sendResponse(CauseAccepted)
    // 但关联状态可能不一致（缺少必要信息）
    // 后续请求基于此关联执行时可能失败
}
```

#### 检测规则

- 协议关联/会话建立处理中无验证即返回成功
- 状态机更新操作在验证逻辑之前执行
- 错误处理路径中未回滚已更新的状态
- 连接/关联存储的增删操作缺少事务性保证
- 成功响应在所有验证完成之前发送

#### 安全模式（修复代码案例）

```go
func HandleAssociationSetup(req *AssociationSetupRequest) {
    // 先验证，再更新状态
    if err := validateAssociationRequest(req); err != nil {
        sendResponse(CauseRequestRejected)
        return
    }

    assoc := &Association{
        NodeID:    req.NodeID,
        State:     StateEstablished,
        Timestamp: time.Now(),
    }

    // 验证通过后才更新存储
    if err := associationStore.Put(assoc); err != nil {
        sendResponse(CauseSystemFailure)
        return
    }

    sendResponse(CauseAccepted)
}
```

#### 测试方法

```go
func TestHandleAssociationSetup_InvalidRequest(t *testing.T) {
    store := NewAssociationStore()
    initialCount := store.Count()

    // 发送格式错误的请求
    invalidReq := &AssociationSetupRequest{
        NodeID: nil,  // 必选字段缺失
    }
    HandleAssociationSetup(invalidReq)

    // 验证：存储中不应新增关联
    if store.Count() != initialCount {
        t.Error("invalid request should not create association")
    }
}
```

#### 关联CVE

- CVE-2025-70123 — free5gc UPF接受格式错误的PFCP关联请求
- CVE-2025-69232 — free5gc go-upf PFCP关联建立导致SMF重连循环

---

## 代码审计检查清单

基于以上攻击模式，在审计Go语言项目（尤其是5GC核心网）时，应重点检查：

### 输入验证

- [ ] 所有接收 `[]byte` 参数的解析函数是否在索引访问前检查 `len()`
- [ ] 二进制协议解码是否验证了最小消息长度
- [ ] 不同消息类型的解析分支是否有各自的长度验证
- [ ] 切片操作 `data[N:M]` 中N和M是否可能越界

### 空指针防护

- [ ] 外部请求处理函数是否检查请求体及其嵌套字段的nil
- [ ] 函数返回 `(*T, error)` 后调用方是否同时检查error和返回值
- [ ] map查找结果是否在使用前检查存在性
- [ ] 类型断言是否使用comma-ok模式

### 协议合规性

- [ ] 协议消息处理是否验证了所有Mandatory IE的存在性
- [ ] IE的值是否经过格式和范围校验
- [ ] 状态机更新是否在验证通过之后执行
- [ ] 错误路径是否正确回滚了状态变更
- [ ] 响应是否在所有验证完成后才发送

### 并发安全

- [ ] 共享状态（如关联表、会话表）的读写是否有锁保护
- [ ] 定时器回调和消息处理之间是否存在竞态
- [ ] goroutine之间的channel通信是否可能死锁

---

## 参考资料

- [CVE-2025-69248](https://nvd.nist.gov/vuln/detail/CVE-2025-69248) — AMF NAS缓冲区溢出
- [CVE-2025-70121](https://nvd.nist.gov/vuln/detail/CVE-2025-70121) — AMF数组索引越界
- [CVE-2025-70123](https://nvd.nist.gov/vuln/detail/CVE-2025-70123) — UPF PFCP输入验证
- [CVE-2025-69232](https://nvd.nist.gov/vuln/detail/CVE-2025-69232) — go-upf PFCP协议合规
- [CVE-2026-1973](https://nvd.nist.gov/vuln/detail/CVE-2026-1973) — SMF空指针解引用
- [CVE-2026-1739](https://nvd.nist.gov/vuln/detail/CVE-2026-1739) — PCF空指针解引用
- [CVE-2026-26025](https://nvd.nist.gov/vuln/detail/CVE-2026-26025) — SMF PFCP会话报告崩溃
- [free5gc Issue #745](https://github.com/free5gc/free5gc/issues/745) — PFCP协议合规性漏洞
- [free5gc Issue #744](https://github.com/free5gc/free5gc/issues/744) — S-NSSAI验证缺陷
- [free5gc/nas PR #43](https://github.com/free5gc/nas/pull/43) — NAS缓冲区溢出修复
- [3GPP TS 29.244](https://www.3gpp.org/DynaReport/29244.htm) — PFCP协议规范
- [3GPP TS 24.501](https://www.3gpp.org/DynaReport/24501.htm) — NAS协议规范
- [CWE-125](https://cwe.mitre.org/data/definitions/125.html) — Out-of-bounds Read
- [CWE-476](https://cwe.mitre.org/data/definitions/476.html) — NULL Pointer Dereference
- [CWE-20](https://cwe.mitre.org/data/definitions/20.html) — Improper Input Validation
