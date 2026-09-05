# Security Assessment Report: InsecureBankv2

## 1. Executive Summary

Static analysis of **InsecureBankv2** (`com.android.insecurebankv2`, version 1.0) revealed critical architectural and configuration security risks. The application exports sensitive core components—including payment transfer, password reset, user tracking content providers, and bank statement views—without requiring any permission guards. Furthermore, the application targets an outdated API level (`targetSdkVersion 22`), permitting unencrypted HTTP traffic by default, and requests excessive dangerous permissions alongside unencrypted hardcoded HTTP URLs.

---

## 2. Vulnerability Summary Table

| ID | Title | Component / Location | Severity |
| :--- | :--- | :--- | :--- |
| **EXPORT_001** | Unprotected Exported Activity | `com.android.insecurebankv2.ViewStatement` | **High** |
| **EXPORT_002** | Unprotected Exported Activity | `com.android.insecurebankv2.ChangePassword` | **High** |
| **EXPORT_003** | Unprotected Exported Activity | `com.android.insecurebankv2.LoginActivity` | **High** |
| **EXPORT_004** | Unprotected Exported Activity | `com.android.insecurebankv2.PostLogin` | **High** |
| **EXPORT_005** | Unprotected Exported Activity | `com.android.insecurebankv2.DoTransfer` | **High** |
| **EXPORT_007** | Unprotected Exported Content Provider | `com.android.insecurebankv2.TrackUserContentProvider` | **High** |
| **EXPORT_006** | Unprotected Exported Broadcast Receiver | `com.android.insecurebankv2.MyBroadCastReceiver` | **Medium** |
| **NET_001** | Outdated Target SDK Permitting Cleartext Traffic | `AndroidManifest.xml` (`targetSdkVersion=22`) | **Medium** |
| **PERM_001** | Dangerous Permission Declared: `SEND_SMS` | `AndroidManifest.xml` | **Medium** |
| **PERM_002** | Dangerous Permission Declared: `GET_ACCOUNTS` | `AndroidManifest.xml` | **Medium** |
| **PERM_003** | Dangerous Permission Declared: `WRITE_EXTERNAL_STORAGE` | `AndroidManifest.xml` | **Medium** |
| **PERM_004** | Dangerous Permission Declared: `READ_CONTACTS` | `AndroidManifest.xml` | **Medium** |
| **PERM_005** | Dangerous Permission Declared: `READ_CALL_LOG` | `AndroidManifest.xml` | **Medium** |
| **PERM_007** | Dangerous Permission Declared: `READ_EXTERNAL_STORAGE` | `AndroidManifest.xml` | **Medium** |
| **PERM_008** | Dangerous Permission Declared: `ACCESS_COARSE_LOCATION` | `AndroidManifest.xml` | **Medium** |
| **PERM_009** | Dangerous Permission Declared: `READ_PHONE_STATE` | `AndroidManifest.xml` | **Medium** |
| **SECRET_001–022** | Insecure Hardcoded HTTP Strings & URLs | DEX String Constants | **Medium** |
| **PERM_006** | Internet Permission Declared: `INTERNET` | `AndroidManifest.xml` | **Low** |

---

## 3. Detailed Findings & Remediation

### 3.1 Unprotected Exported Application Components

#### Findings: EXPORT_001, EXPORT_002, EXPORT_003, EXPORT_004, EXPORT_005, EXPORT_006, EXPORT_007

* **Component Locations**:
  * `com.android.insecurebankv2.ViewStatement` (Activity)
  * `com.android.insecurebankv2.ChangePassword` (Activity)
  * `com.android.insecurebankv2.LoginActivity` (Activity)
  * `com.android.insecurebankv2.PostLogin` (Activity)
  * `com.android.insecurebankv2.DoTransfer` (Activity)
  * `com.android.insecurebankv2.MyBroadCastReceiver` (BroadcastReceiver)
  * `com.android.insecurebankv2.TrackUserContentProvider` (ContentProvider)
* **Evidence**: `android:exported=true` declared without `android:permission` requirements.

#### Explanation
An exported component is accessible to any third-party application installed on the same device. When sensitive components (such as funds transfer screens, password change interfaces, and database content providers) are exported without protection, malicious apps can directly invoke or query them, bypassing internal authentication controls and authorization checks.

#### Real-World Attack Scenario
1. **Bypassing Authentication**: A malicious application installed on the user's device launches an explicit intent to `com.android.insecurebankv2.DoTransfer` or `com.android.insecurebankv2.ChangePassword`. Because these activities do not verify if the user is authenticated prior to rendering or performing actions, the attacker triggers an unauthorized fund transfer or updates the victim's account credentials.
2. **Data Leakage via Content Provider**: A malicious app queries `content://com.android.insecurebankv2.TrackUserContentProvider` directly to extract user tracking data, transaction histories, or sensitive personal information saved in the underlying database.

#### Remediation
1. **Set `android:exported="false"`** for all components that do not need to be launched by third-party applications in `AndroidManifest.xml`:
   ```xml
   <activity 
       android:name=".DoTransfer" 
       android:exported="false" />
   <provider 
       android:name=".TrackUserContentProvider" 
       android:authorities="com.android.insecurebankv2.TrackUserContentProvider"
       android:exported="false" />
   ```
2. **Apply Permission Guards**: If a component must be exported for external integration, enforce signature-level custom permissions:
   ```xml
   <permission 
       android:name="com.android.insecurebankv2.CUSTOM_PERMISSION" 
       android:protectionLevel="signature" />
   ```

---

### 3.2 Outdated Target SDK & Cleartext HTTP Traffic

#### Finding: NET_001
* **Location**: `AndroidManifest.xml` → `<uses-sdk android:targetSdkVersion="22" />`
* **Evidence**: `android:targetSdkVersion="22"`

#### Explanation
Targeting API level 22 (Android 5.1) disables modern platform security defenses introduced in Android 6.0 (API 23) and Android 9.0 (API 28). Specifically, API levels below 28 permit unencrypted plain-text HTTP traffic by default across the entire application, making API calls susceptible to network interception.

#### Real-World Attack Scenario
An attacker positioned on the same local Wi-Fi network (e.g., public Wi-Fi) executes a Man-in-the-Middle (MitM) attack. Because the app targets SDK 22 and permits cleartext HTTP, the attacker intercepts API requests containing session tokens, account login credentials, and transaction requests in plain text, altering or stealing the data in real time.

#### Remediation
1. **Update `targetSdkVersion`**: Update the build configuration to target the latest Android API level (API 34+).
2. **Configure Network Security Configuration**: Enforce HTTPS communication across the application by declaring a `network_security_config.xml`:
   ```xml
   <!-- res/xml/network_security_config.xml -->
   <network-security-config>
       <base-config cleartextTrafficPermitted="false">
           <trust-anchors>
               <certificates src="system" />
           </trust-anchors>
       </base-config>
   </network-security-config>
   ```
3. Reference it in `AndroidManifest.xml`:
   ```xml
   <application android:networkSecurityConfig="@xml/network_security_config" ...>
   ```

---

### 3.3 Over-Privileged Dangerous Permission Declarations

#### Findings: PERM_001, PERM_002, PERM_003, PERM_004, PERM_005, PERM_006, PERM_007, PERM_008, PERM_009

* **Location**: `AndroidManifest.xml`
* **Evidence**:
  * `android.permission.SEND_SMS` (PERM_001)
  * `android.permission.GET_ACCOUNTS` (PERM_002)
  * `android.permission.WRITE_EXTERNAL_STORAGE` (PERM_003)
  * `android.permission.READ_CONTACTS` (PERM_004)
  * `android.permission.READ_CALL_LOG` (PERM_005)
  * `android.permission.INTERNET` (PERM_006)
  * `android.permission.READ_EXTERNAL_STORAGE` (PERM_007)
  * `android.permission.ACCESS_COARSE_LOCATION` (PERM_008)
  * `android.permission.READ_PHONE_STATE` (PERM_009)

#### Explanation
Declaring unused or excessive dangerous permissions expands the attack surface of the app. Access to sensitive resources like SMS, external storage, call logs, contacts, and phone state allows compromised app dependencies or exploited components to perform unintended actions or extract sensitive user telemetry. Additionally, storing banking data on shared external storage (`READ/WRITE_EXTERNAL_STORAGE`) makes it accessible to any application with storage access.

#### Real-World Attack Scenario
If the app writes bank statements, transaction logs, or temporary session files to public external storage (`WRITE_EXTERNAL_STORAGE`), a malicious application on the device with `READ_EXTERNAL_STORAGE` permissions can passively monitor and extract financial records without requiring root privilege.

#### Remediation
1. **Principle of Least Privilege**: Remove all permission requests that are not strictly necessary for core banking functionality (e.g., `READ_CALL_LOG`, `READ_CONTACTS`, `SEND_SMS`).
2. **Use App-Specific Storage**: Move sensitive data from external shared storage to app-internal protected storage (`Context.getFilesDir()`) which requires no system storage permissions:
   ```xml
   <!-- Remove unnecessary permissions from AndroidManifest.xml -->
   <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" tools:node="remove" />
   ```

---

### 3.4 Insecure Hardcoded HTTP URLs and Schema Constants

#### Findings: SECRET_001 through SECRET_022

* **Location**: DEX string constants
* **Evidence**:
  * `http://goo.gl/8Rd3yj` (SECRET_001)
  * `http://goo.gl/naFqQk` (SECRET_002)
  * `http://plus.google.com/` (SECRET_003)
  * `http://schema.org/ActivateAction` (SECRET_004)
  * `http://schema.org/ActiveActionStatus` (SECRET_005)
  * `http://schema.org/AddAction` (SECRET_006)
  * `http://schema.org/BookmarkAction` (SECRET_007)
  * `http://schema.org/CommunicateAction` (SECRET_008)
  * `http://schema.org/CompletedActionStatus` (SECRET_009)
  * `http://schema.org/FailedActionStatus` (SECRET_010)
  * `http://schema.org/FilmAction` (SECRET_011)
  * `http://schema.org/LikeAction` (SECRET_012)
  * `http://schema.org/ListenAction` (SECRET_013)
  * `http://schema.org/PhotographAction` (SECRET_014)
  * `http://schema.org/ReserveAction` (SECRET_015)
  * `http://schema.org/SearchAction` (SECRET_016)
  * `http://schema.org/ViewAction` (SECRET_017)
  * `http://schema.org/WantAction` (SECRET_018)
  * `http://schema.org/WatchAction` (SECRET_019)
  * `http://schemas.android.com/apk/lib/com.google.android.gms.pl…` (SECRET_020)
  * `http://www.google-analytics.com` (SECRET_021)
  * `http://www.google.com` (SECRET_022)

#### Explanation
Hardcoded unencrypted HTTP URLs (such as shortened links and service endpoints) expose traffic to wiretapping, request tampering, and redirections. Even when URLs represent metadata schemas (e.g., `schema.org`), using plain `http://` endpoints for operational network requests leads to insecure communication patterns.

#### Real-World Attack Scenario
An attacker on an untrusted network intercepts traffic destined for `http://goo.gl/8Rd3yj` or `http://www.google-analytics.com` and performs DNS spoofing or HTTP redirection, serving malicious payloads or capturing user tracking details.

#### Remediation
1. **Migrate to HTTPS**: Ensure all remote URLs and endpoint references use `https://` secure transport schemes.
2. **Remove Unused Third-Party Libraries**: Clean up unused SDK constants, schema identifiers, and legacy URL shortcuts from the code base.