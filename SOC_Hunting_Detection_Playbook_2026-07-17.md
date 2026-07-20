# SOC 狩獵假設與 SIEM 偵測規則草稿
**文件日期：** 2026-07-17  
**依據情資：** CISA KEV 2026-07-14～16、廠商 PSIRT、CISA SharePoint Alert  
**分類：** TLP:AMBER（內部 SOC 使用；部署前請依環境調校）  
**用途：** 高優先 KEV 之威脅狩獵假設（Hypothesis）＋ SIEM 規則草稿＋資產清冊對照模板

---

## 0. 使用說明

| 項目 | 說明 |
|------|------|
| 規則語法 | 以 **Splunk SPL** 與 **Microsoft Sentinel KQL** 雙版本提供；欄位名請對應貴司 CIM／ASIM 正規化 |
| 嚴重度 | Critical / High / Medium |
| 誤報 | 每則附 Tuning 建議；**先 shadow mode 7 天**再自動工單 |
| 法律／授權 | PoC 掃描僅限**自有資產**；禁止對外未授權掃描 |
| 調查窗口 | 建議回溯 **至少 30–90 天**（zero-day 可能早於公開日） |

### 嚴重性對應建議處置

| Severity | 初始回應時限 | 建議 |
|----------|--------------|------|
| Critical | 1 小時 | 隔離／Assume Breach 流程 |
| High | 4 小時 | 優先 triage + 資產負責人會同 |
| Medium | 1 個工作日 | 納入狩獵佇列 |

---

## 1. 狩獵假設清單（Hypothesis Catalog）

### H-SMA-01｜SonicWall SMA1000 遭 SSRF／串連 RCE 初始存取
- **CVE：** CVE-2026-15409, CVE-2026-15410  
- **假設：** 攻擊者對網際網路暴露之 SMA1000 利用 SSRF（及可能之後認證 code injection），植入異常 API 路由、竊取 session／TOTP seed，並以合法 VPN 通道橫向移動。  
- **資料來源：** SMA `extraweb_access.log`、`ctrl-service.log`、`/var/lib/unit/conf.json`、VPN 認證日誌、IdP／AD 登入、EDR  
- **預期證據（廠商 IOC）：**
  1. `extraweb_access.log`：`/__api__/login` 或 `/__api__/logout` 且 **HTTP 200**
  2. `extraweb_access.log`：`/wsproxy` 含可疑 `host` 參數且 **HTTP 101**
  3. `ctrl-service.log`：hotfix rollback／removal 路徑含 **path traversal**（如 `../`）
  4. `conf.json` 出現 **不應存在** 的 `/__api__/login`、`/__api__/logout` 路由
- **驗證步驟：** 修補狀態確認 → 上述 4 項 IOC 全量搜尋 → 若命中則 **重灌／重建 appliance**、**全數輪替帳密與 TOTP**、撤銷 session  
- **False Negative 風險：** 日誌未集中、日誌留存不足 30 天  
- **MITRE ATT&CK：** T1190 Exploit Public-Facing Application → T1078 Valid Accounts → T1556 MFA Modify

### H-FSB-01｜FortiSandbox 未驗證 Command Injection
- **CVE：** CVE-2026-39808, CVE-2026-25089（相關：CVE-2026-39813 認證繞過）  
- **假設：** 攻擊者對暴露之 FortiSandbox HTTP 介面送出特製請求（如 job-detail／API），以 root 執行命令，可能部署反彈 shell 或竄改沙箱判決。  
- **資料來源：** FortiSandbox HTTP access log、系統 audit、進程建立、DNS、對外連線  
- **預期證據：**
  1. URI 含 `fortisandbox/job-detail`、`tracer-behavior` 或異常 `jid=` 參數（含 shell metachar：`|` `` ` `` `;` `$()`）
  2. 未預期的 `sh`/`bash`/`curl`/`wget` 由 sandbox 服務帳號啟動
  3. 管理介面來源 IP 非維運白名單
  4. 短時間大量 4xx/5xx 後出現 200（掃描後利用）
- **驗證步驟：** 版本 ≥ 修補版 → 管理面是否公網 → 日誌／EDR 狩獵 → 必要時離線鑑識  
- **MITRE：** T1190 → T1059 Command and Scripting Interpreter → T1105 Ingress Tool Transfer

### H-SP-01｜SharePoint on-prem 利用鏈（認證繞過／反序列化 RCE）
- **CVE：** CVE-2026-32201, CVE-2026-45659, CVE-2026-56164, CVE-2026-58644（關注 CVE-2026-55040）  
- **假設：** 攻擊者對 on-prem SharePoint 進行 ToolPane／SignOut 相關利用，取得 RCE，竊取 **IIS machine keys**，部署 webshell，並以 viewstate 或 backdoor 持久化。  
- **資料來源：** IIS／SharePoint ULS、Windows Security、Sysmon、MDAV／AMSI、MDE  
- **預期證據：**
  1. AMSI：`Exploit:Script/SuspSignoutReqBody.A`、`ToolPaneAuthBypass.A`、`ToolPaneAuthBypass.C`
  2. MDAV：`Backdoor:MSIL/LeakFang.A!dha`（IIS 機密相關後滲透）
  3. HTTP：`POST` 至 `/_layouts/15/ToolPane.aspx`（含 `DisplayMode=Edit`）
  4. Referer：`/_layouts/SignOut.aspx` 搭配異常 POST（歷史 ToolShell 手法，仍具狩獵價值）
  5. `w3wp.exe` 衍生 `cmd.exe`/`powershell.exe`/`csc.exe`；LAYOUTS／TEMP 下新 aspx
  6. machineKey／web.config 異常讀取
- **驗證步驟：** 修補 KB 確認 → AMSI Full Mode → 狩獵 webshell → **先清入侵再輪 machine key**  
- **MITRE：** T1190 → T1505.003 Web Shell → T1552 Unsecured Credentials → T1027

### H-EBS-01｜Oracle EBS Payments 未驗證檔案讀取／接管
- **CVE：** CVE-2026-46817  
- **假設：** 攻擊者未驗證對 `/OA_HTML/ibytransmit` 送出 XML `DeliveryRequest`（如 `CODEX_PULL` + `FULL_FILE_PATH`），讀取敏感檔或進一步接管 Payments。  
- **資料來源：** Oracle HTTP Server／OHS／WLS access log、WAF、EBS 應用日誌  
- **預期證據：**
  1. `POST /OA_HTML/ibytransmit` 來自非批核系統 IP
  2. Body／參數含 `DeliveryRequest`、`CODEX_PULL`、`FULL_FILE_PATH`
  3. User-Agent 含 `ibytransmit`、`poc`、`lab` 等異常字串（例：曾見 `ibytransmit-lab-poc/1.0`）
  4. 回應體異常大或含 `/etc/passwd`、`web.xml`、連線字串特徵
- **驗證步驟：** 確認 May 2026 CSPU+ → 網路是否可達 → 30 天 access log 全掃 → 金鑰／DB 密碼輪替評估  
- **MITRE：** T1190 → T1005 Data from Local System → T1552

### H-ADFS-01｜ADFS 異常宣告／權限邊界繞過
- **CVE：** CVE-2026-56155  
- **假設：** 攻擊者利用 ADFS 存取控制粒度不足，取得過寬之 token／宣告，存取本不應允許之資源。  
- **資料來源：** ADFS Admin／Security 日誌、Entra ID／AD 登入、應用 SSO 日誌  
- **預期證據：** 異常 Relying Party、高權限 claim 突變、非常用 client 的成功 SSO、修補前之失敗後突然成功  
- **MITRE：** T1078 → T1550 Use Alternate Authentication Material

### H-KNX-01｜KNX／BMS 異常鎖定或裝置清除
- **CVE：** CVE-2023-4346  
- **假設：** 攻擊者對暴露或弱隔離之 KNX 匯流排／閘道，濫用鎖定機制清除裝置或寫入 BCU key。  
- **資料來源：** KNX 閘道日誌、OT IDS、防火牆「IT→OT」連線  
- **預期證據：** 非維護窗口之大量 device reset／key set、來自 IT／網際網路之 KNXnet/IP  
- **MITRE ICS：** T0883 Internet Accessible Device、T0836 Modify Parameter、T0813 Denial of Control

### H-LAT-01｜邊界設備淪陷後之橫向與身分濫用（通用）
- **假設：** SMA／FortiSandbox／SharePoint 任一淪陷後，攻擊者使用竊得 VPN／AD 帳號登入內網，進行偵察與備份／檔案伺服器存取。  
- **資料來源：** VPN 成功登入、AD 異常登入、Pure／Veeam、SMB 大量讀取  
- **預期證據：** 同一帳號「設備管理 IP → 內網多主機」；非辦公時段 MFA 重綁；新 VPN 裝置指紋  
- **MITRE：** T1021 Remote Services、T1078、T1083、T1560

---

## 2. SIEM 偵測規則草稿

> 欄位請替換：`index=...`、`DeviceProduct`、`UrlOriginal`、`src`、`http_status` 等。

---

### 2.1 SonicWall SMA1000

#### DET-SMA-001 — 可疑 API 登入路徑（Critical）

**SPL**
```spl
index=network OR index=vpn sourcetype=*sonicwall* OR sourcetype=*extraweb*
(uri_path="*/__api__/login" OR uri_path="*/__api__/logout" OR uri="*/__api__/login*" OR uri="*/__api__/logout*")
status=200
| stats count min(_time) as first_seen max(_time) as last_seen values(src) as src_ip values(dest) as dest by uri, status
| where count > 0
```

**KQL（自訂 Logs 或 CEF 匯入後調整）**
```kql
// 假設已將 SMA access log 收至 CustomTable 或 CommonSecurityLog
CommonSecurityLog
| where DeviceVendor has_any ("SonicWall", "SONICWALL")
| where RequestURL has_any ("/__api__/login", "/__api__/logout")
| where ResponseCode == 200
| summarize count(), make_set(SourceIP), min(TimeGenerated), max(TimeGenerated) by RequestURL, DeviceAddress
```

**告警說明：** 合法設定不應存在這些 URI；命中高度可疑。  
**Tuning：** 無；命中即 IR。

---

#### DET-SMA-002 — wsproxy 可疑 SSRF（Critical）

**SPL**
```spl
index=network sourcetype=*extraweb* OR sourcetype=*sonicwall*
(uri_path="*/wsproxy*" OR uri="*/wsproxy*")
status=101
| regex uri="(?i)(host=|Host:).*"
| eval suspicious=if(match(uri, "(?i)(127\.0\.0\.1|localhost|169\.254\.|metadata|internal|0\.0\.0\.0|file:)"), 1, 0)
| where suspicious=1 OR match(uri, "(?i)host=[^&]+")
| table _time, src, dest, uri, status
```

**KQL**
```kql
CommonSecurityLog
| where DeviceVendor has "SonicWall"
| where RequestURL has "/wsproxy"
| where ResponseCode == 101
| where RequestURL matches regex @"(?i)(127\.0\.0\.1|localhost|169\.254\.|metadata|internal)"
   or isnotempty(extract(@"host=([^&]+)", 1, RequestURL))
| project TimeGenerated, SourceIP, DeviceAddress, RequestURL, ResponseCode
```

---

#### DET-SMA-003 — Hotfix path traversal（Critical）

**SPL**
```spl
index=network sourcetype=*ctrl-service* OR message="*hotfix*"
| regex _raw="(?i)hotfix.*(removal|rollback|\.\./|%2e%2e)"
| table _time, host, _raw
```

**處置：** 命中 → 依廠商指引重灌並輪替 TOTP／密碼。

---

### 2.2 FortiSandbox

#### DET-FSB-001 — Command injection URI 模式（Critical）

**SPL**
```spl
index=web OR index=proxy OR index=fortinet
(uri="*fortisandbox*" OR uri="*job-detail*" OR uri="*tracer-behavior*" OR http_user_agent="*FortiSandbox*")
| regex uri="(?i)(jid=.*(\||%7c|`|%60|;|%3b|\$\(|%24%28)|cmd=|exec)"
| table _time, src, dest, uri, status, http_user_agent
```

**KQL**
```kql
W3CIISLog
// 或 CommonSecurityLog / 代理日誌
| where csUriStem has_any ("job-detail", "tracer-behavior", "fortisandbox")
| where csUriQuery matches regex @"(?i)(\||%7c|`|;|\$\()"
| project TimeGenerated, cIP, sIP, csUriStem, csUriQuery, scStatus
```

**Tuning：** 僅監控 FortiSandbox VIP／已知主機；內部漏洞掃描 IP 加入 allowlist（獨立 tag）。

---

#### DET-FSB-002 — Sandbox 主機異常子程序（High）

**SPL（Sysmon／EDR）**
```spl
index=edr OR sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational OR sourcetype=sysmon
EventCode=1
(parent_process_name="*sandbox*" OR host IN (fortisandbox_asset_list))
(process_name IN ("cmd.exe", "powershell.exe", "bash", "sh", "curl", "wget", "python", "nc", "ncat"))
| table _time, host, user, parent_process_name, process_name, process_command_line
```

**KQL**
```kql
DeviceProcessEvents
| where DeviceName has_any ("sandbox", "fsb", "fortisandbox") // 改為資產標籤
| where InitiatingProcessFileName has_any ("httpd", "nginx", "java", "python", "fortisandbox")
| where FileName in~ ("cmd.exe", "powershell.exe", "bash", "curl.exe", "wget", "sh")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

---

### 2.3 Microsoft SharePoint

#### DET-SP-001 — AMSI／MDAV 利用簽章（Critical）

**SPL**
```spl
index=defender OR index=windows sourcetype=*WinEvent* OR sourcetype=*Microsoft-Windows-Windows\ Defender*
(ThreatName="*SuspSignoutReqBody*" OR ThreatName="*ToolPaneAuthBypass*" OR ThreatName="*LeakFang*"
 OR SignatureName="*SuspSignoutReqBody*" OR SignatureName="*ToolPaneAuthBypass*" OR SignatureName="*LeakFang*"
 OR Message="*SuspSignoutReqBody*" OR Message="*ToolPaneAuthBypass*" OR Message="*LeakFang*")
| table _time, host, ThreatName, SignatureName, Message, src
```

**KQL**
```kql
DeviceEvents
| where ActionType has_any ("AntivirusDetection", "AntivirusThreatDetected")
    or AdditionalFields has_any ("SuspSignoutReqBody", "ToolPaneAuthBypass", "LeakFang")
| where tostring(AdditionalFields) has_any (
    "SuspSignoutReqBody",
    "ToolPaneAuthBypass",
    "LeakFang"
)
    or FileName has "LeakFang"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, AdditionalFields
```

另於 **AlertInfo / AlertEvidence** 搜尋同一簽章名稱。

---

#### DET-SP-002 — ToolPane／SignOut 可疑 HTTP（Critical）

**SPL**
```spl
index=web sourcetype=iis OR sourcetype=ms:iis:auto
| eval uri_lower=lower(uri_stem)
| where (match(uri_lower, "toolpane\.aspx") AND method="POST")
    OR (match(cs_Referer, "(?i)SignOut\.aspx") AND method="POST")
| stats count by src_ip, dest, uri_stem, method, cs_Referer, status
| where count >= 1
```

**KQL**
```kql
W3CIISLog
| where csMethod == "POST"
| where csUriStem has "ToolPane.aspx"
    or (csUriStem has "SignOut.aspx")
    or (csReferer has "SignOut.aspx" and csUriStem has "ToolPane")
| summarize count(), make_set(scStatus) by bin(TimeGenerated, 1h), cIP, sIP, csUriStem, csReferer
```

**Tuning：** 合法管理 POST 可能存在；以 **非內網管理網段 + POST + 異常 UA** 加權。

---

#### DET-SP-003 — w3wp 衍生 shell（Critical）

**SPL**
```spl
index=sysmon EventCode=1 parent_process_name="w3wp.exe"
process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "csc.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe")
| table _time, host, user, process_name, process_command_line, parent_process_name
```

**KQL**
```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "csc.exe", "mshta.exe", "certutil.exe")
| where DeviceName in (SharePointServerList) // 資產標籤
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

---

#### DET-SP-004 — 疑似 webshell 寫入（High）

**SPL**
```spl
index=sysmon (EventCode=11 OR EventCode=2)
(file_path="*\\LAYOUTS\\*" OR file_path="*\\TEMPLATE\\*" OR file_path="*\\FRONTENDS\\*" OR file_path="*\\Temporary ASP.NET*")
(file_name="*.aspx" OR file_name="*.ashx" OR file_name="*.asmx")
| table _time, host, file_path, file_name, process_name, user
```

**KQL**
```kql
DeviceFileEvents
| where ActionType in ("FileCreated", "FileRenamed")
| where FolderPath has_any (@"LAYOUTS", @"TEMPLATE", @"Temporary ASP.NET Files")
| where FileName endswith ".aspx" or FileName endswith ".ashx"
| where InitiatingProcessFileName in~ ("w3wp.exe", "cmd.exe", "powershell.exe")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessAccountName
```

---

### 2.4 Oracle E-Business Suite

#### DET-EBS-001 — ibytransmit 未授權存取（Critical）

**SPL**
```spl
index=web OR index=oracle
(uri_path="*/OA_HTML/ibytransmit*" OR uri="*/OA_HTML/ibytransmit*")
method=POST
| eval ua_sus=if(match(http_user_agent, "(?i)(poc|lab|ibytransmit|scanner|curl|python-requests)"), 1, 0)
| eval body_sus=if(match(_raw, "(?i)(CODEX_PULL|FULL_FILE_PATH|DeliveryRequest|/etc/passwd|web\.xml)"), 1, 0)
| where ua_sus=1 OR body_sus=1 OR src NOT IN (ebs_integration_allowlist)
| table _time, src, dest, uri, status, http_user_agent
```

**KQL**
```kql
// 以 WAF / HTTP 日誌為準；Body 需有完整記錄或 WAF 規則
CommonSecurityLog
| where RequestURL has "/OA_HTML/ibytransmit"
| where RequestMethod == "POST"
| where RequestClientApplication has_any ("poc", "lab", "ibytransmit", "curl", "python")
    or Message has_any ("CODEX_PULL", "FULL_FILE_PATH", "DeliveryRequest", "/etc/passwd")
    or RequestURL has "FULL_FILE_PATH"
| project TimeGenerated, SourceIP, DestinationIP, RequestURL, RequestClientApplication, Message
```

**WAF 虛擬修補建議簽章關鍵字：**  
`/OA_HTML/ibytransmit` + (`CODEX_PULL` OR `FULL_FILE_PATH` OR `DeliveryRequest`) → Block／Log

---

### 2.5 ADFS

#### DET-ADFS-001 — 修補前後異常 SSO 尖峰（High）

**SPL**
```spl
index=wineventlog source="AD FS" OR sourcetype="WinEventLog:AD FS*"
(EventCode=1200 OR EventCode=1201 OR EventCode=1202 OR EventCode=1203 OR EventCode=1206)
| bucket _time span=1h
| stats count by _time, host, EventCode
| eventstats avg(count) as avg_c stdev(count) as std_c
| where count > avg_c + 3*std_c
```

**KQL**
```kql
Event
| where EventLog == "AD FS/Admin" or Source == "AD FS Auditing"
| summarize count() by bin(TimeGenerated, 1h), Computer
| extend baseline = 100 // 改為環境基線或 series_decompose_anomalies
| where count_ > baseline * 3
```

**補充：** 完成 CVE-2026-56155 修補後，對 **新出現的 high-privilege claims** 做一週 diff。

---

### 2.6 橫向與身分（通用）

#### DET-LAT-001 — VPN 帳號短時間多主機（High）

**SPL**
```spl
index=vpn OR index=auth action=success
| stats dc(dest) as dest_count values(dest) as dests by user, src
| where dest_count > 10
```

**KQL**
```kql
SigninLogs
// 或 VpnConnectionEvents / AAD
| where ResultType == 0
| summarize dcount(IPAddress), make_set(IPAddress), dcount(ResourceDisplayName) by UserPrincipalName, bin(TimeGenerated, 1h)
| where dcount_IPAddress > 5
```

---

#### DET-LAT-002 — MFA 重綁／新裝置異常（High）

**KQL（Entra ID）**
```kql
AuditLogs
| where OperationName has_any ("User registered security info", "User deleted security info", "StrongAuthentication")
| where Result == "success"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, ResultReason
```

---

## 3. 資產清冊對照模板（請填寫後可精準對照）

請複製下表，回填後可做 KEV × 暴露面矩陣。

| AssetID | Hostname | 產品／版本 | 網段 | Internet-facing (Y/N) | 管理 URL／VIP | 負責人 | 最後修補日 | 對應 CVE／KEV | 修補狀態 (Open/InProgress/Closed) | 日誌是否進 SIEM | 備註 |
|---------|----------|------------|------|----------------------|---------------|--------|------------|---------------|-----------------------------------|-----------------|------|
| | | SonicWall SMA1000 / | | | | | | 15409,15410 | | | |
| | | FortiSandbox / | | | | | | 39808,25089 | | | |
| | | SharePoint SE/2019/2016 | | | | | | 58644,56164,... | | | |
| | | Oracle EBS 12.2.x | | | | | | 46817 | | | |
| | | ADFS / | | | | | | 56155 | | | |
| | | KNX Gateway / | | | | | | 2023-4346 | | | |
| | | Rockwell / Schneider / | | | | | | ICS Advisories 7月 | | | |

### 優先處置矩陣（無完整清冊時之預設）

| 條件 | 優先級 |
|------|--------|
| Internet-facing + KEV + 未修補 | **P0** |
| Internet-facing + KEV + 已修補但未做 IOC 狩獵 | **P0**（仍要狩獵） |
| 內網 only + KEV + 未修補 | **P1** |
| ICS／BMS 可自 IT 路由到達 | **P1** |
| 已修補 + 狩獵無異常 + 日誌完整 | **P2** 監控 |

---

## 4. 72 小時狩獵作戰時程（建議）

| 時段 | 行動 |
|------|------|
| **0–4h** | 凍結資產清單；SMA IOC 四項全掃；SharePoint AMSI／ToolPane；對外暴露下線或 ACL |
| **4–24h** | FortiSandbox／Oracle ibytransmit 全量日誌；EDR w3wp／sandbox 子程序；憑證與 TOTP 輪替決策 |
| **24–72h** | 橫向與 MFA 狩獵；webshell 掃瞄；修補驗證；關閉告警 false positive；向管理層回報 |
| **Day 4–14** | 每 24h 複跑規則；關注新 PoC／CISA 更新；EPSS 再評級 |

---

## 5. 調查檢查清單（IR 快速卡）

### SonicWall SMA1000
- [ ] 韌體 ≥ 官方 fixed build  
- [ ] `extraweb_access.log`：`/__api__/login|logout` + 200  
- [ ] `/wsproxy` + 可疑 host + 101  
- [ ] `ctrl-service.log` path traversal hotfix  
- [ ] `conf.json` 非法路由  
- [ ] 若任一命中：重灌、輪替所有密碼與 **TOTP seed**、撤銷 session  

### FortiSandbox
- [ ] 版本已修補  
- [ ] 管理面不在公網  
- [ ] URI 含 shell metachar 之請求  
- [ ] 異常子程序／對外 C2  

### SharePoint
- [ ] 7 月安全性更新已安裝並驗證  
- [ ] AMSI Full Mode  
- [ ] ToolPane／SignOut 狩獵  
- [ ] webshell 與 w3wp → shell  
- [ ] **先清入侵 → 再輪 machine keys**  

### Oracle EBS
- [ ] CSPU／修補已套用  
- [ ] `/OA_HTML/ibytransmit` POST 審計  
- [ ] 整合系統 allowlist  

---

## 6. 規則部署優先順序

| 順序 | Rule ID | 嚴重度 | 依賴資料 |
|------|---------|--------|----------|
| 1 | DET-SMA-001, 002, 003 | Critical | SMA 日誌必須進 SIEM |
| 2 | DET-SP-001, 002, 003 | Critical | IIS + Defender |
| 3 | DET-FSB-001, 002 | Critical | Web／EDR |
| 4 | DET-EBS-001 | Critical | OHS／WAF body log |
| 5 | DET-LAT-001, 002 | High | VPN／IdP |
| 6 | DET-ADFS-001 | High | ADFS audit 需啟用 |
| 7 | KNX／OT | Medium | 視 OT 可見度 |

---

## 7. 版本紀錄

| 版本 | 日期 | 說明 |
|------|------|------|
| 1.0 | 2026-07-17 | 初版：對應當日 KEV 高優先情資 |

**免責：** 本文件為防禦與偵測用途之操作草稿，需依實際日誌 schema、資產與授權環境調校後部署。利用細節以 CISA／廠商最新公告為準。
