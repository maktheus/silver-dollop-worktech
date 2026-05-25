# Threat Research — GuardApp
## "Think Like an Attacker, Act Like an Engineer"

> Este documento mapeia como um atacante real abordaria o GuardApp —
> camada por camada — e o que um engenheiro deve fazer em resposta.
> Inclui ataques **além do que está implementado** no projeto atual.

---

## 1. Modelo de Ameaça

Antes de atacar uma defesa, o atacante define seus objetivos:

| Objetivo | Perfil | Exemplo concreto |
|---|---|---|
| **Fraud / Account takeover** | Emulador farm | Bot bancário rodando 500 instâncias no PC |
| **Cheating / Game hacking** | Usuário avançado | Modificar valores de moeda in-game em runtime |
| **Malware / RAT** | Threat actor | App trojanizado que passa pelo Play Protect |
| **Pentest / Bug bounty** | Pesquisador | Forçar fluxos de autenticação não protegidos |
| **Privacy bypass** | Clone de app | 2 contas de WhatsApp sem solução oficial |

> **Verdade fundamental:** toda detecção que roda no processo do app
> roda no **território do atacante**. Ele controla a memória, a CPU e
> o sistema de arquivos. Nós somos convidados na casa deles.

---

## 2. Superfície de Ataque

```
┌─────────────────────────────────────────────────────┐
│                    GUARDAPP APK                     │
│                                                     │
│  ┌──────────────┐  ┌─────────────────────────────┐  │
│  │ EmulatorAnal │  │ VirtualizationAnalyzer      │  │
│  │   .kt        │  │   Port 27042, /proc/net/tcp │  │
│  └──────────────┘  │   File artifacts            │  │
│  ┌──────────────┐  │   ClassLoader probe         │  │
│  │ CloneAnalyz  │  └─────────────────────────────┘  │
│  │   .kt        │  ┌─────────────────────────────┐  │
│  │ PackageMgr   │  │ SignatureAnalyzer.kt         │  │
│  │ File probes  │  │   X.509 cert, SHA-256        │  │
│  └──────────────┘  │   Installer source           │  │
│  ┌──────────────┐  └─────────────────────────────┘  │
│  │ RootDetector │                                    │
│  │   su paths   │  TUDO ISSO RODA DENTRO DO         │
│  │   props      │  PROCESSO DO ATACANTE             │
│  └──────────────┘  ← PROBLEMA FUNDAMENTAL           │
└─────────────────────────────────────────────────────┘
```

---

## 3. Ataques por Camada de Detecção

### 3.1 Emulator Detection Bypass

**O que o GuardApp verifica:**
- `Build.FINGERPRINT`, `Build.MODEL`, `Build.MANUFACTURER` vs strings conhecidas (`goldfish`, `sdk_gphone`, `generic`)
- Propriedades de sistema via reflection (`qemu.sf.fake_camera`, `ro.kernel.qemu`)
- Arquivos QEMU (`/dev/socket/qemud`, `/dev/qemu_pipe`)
- `/proc/cpuinfo` procurando `intel` / `goldfish`

---

#### Ataque 1 — Build Property Spoofing via ROM customizada

O atacante compila AOSP com as propriedades alteradas:

```bash
# device/google/cuttlefish/shared/config/config.ini
ro.product.model=Pixel 9 Pro
ro.product.manufacturer=Google
ro.build.fingerprint=google/shiba/shiba:15/AP31.240617.009/12305715:user/release-keys
ro.hardware=shiba
```

Resultado: nenhuma string suspeita encontrada. Custo: alto (requer compilar ROM).
Usado por **farms profissionais** de emulação.

---

#### Ataque 2 — Frida hookeia os campos Build em runtime

```javascript
Java.perform(function() {
    var Build = Java.use('android.os.Build');
    Build.FINGERPRINT.value = 'google/shiba/shiba:15/AP31.240617.009/12305715:user/release-keys';
    Build.MODEL.value       = 'Pixel 9 Pro';
    Build.MANUFACTURER.value = 'Google';
    Build.HARDWARE.value    = 'shiba';

    // Intercepta System.getProperty para apagar props qemu
    var System = Java.use('java.lang.System');
    System.getProperty.overload('java.lang.String').implementation = function(key) {
        if (key.includes('qemu') || key.includes('goldfish')) return null;
        return this.getProperty(key);
    };

    // Intercepta File.exists() para arquivos QEMU
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var p = this.getAbsolutePath();
        if (p.includes('qemud') || p.includes('qemu_pipe') || p.includes('vbox')) return false;
        return this.exists();
    };
});
```

---

#### Ataque 3 — Xposed Module (sem Frida, sem processo externo)

```kotlin
@XposedHook
class BuildSpoofer : IXposedHookLoadPackage {
    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        XposedHelpers.findAndHookField(Build::class.java, "FINGERPRINT",
            object : XC_FieldGet() {
                override fun beforeFieldGet(param: FieldGetParam) {
                    param.result = "google/shiba/shiba:15/AP3..."
                }
            }
        )
    }
}
```

**Gaps atuais:**
- Não detecta ROMs com Build props legítimas (farms profissionais)
- Não usa Play Integrity API (hardware attestation via TEE)
- Não verifica **consistência cross-prop** — um Pixel 9 Pro real teria
  `ro.hardware=shiba` + `ro.board.platform=kalama` ao mesmo tempo.
  ROMs fake frequentemente erram combinações menos óbvias.

---

### 3.2 Clone App Detection Bypass

**O que o GuardApp verifica:**
- 24 packages conhecidos via PackageManager
- `uid / 100_000 != 0` (multi-user offset)
- `context.dataDir` fora de `/data/data/` ou `/data/user/0/`
- `/proc/self/maps` com padrões de libs de clone

---

#### Ataque 1 — Package Renaming com apktool

```bash
apktool d com.lbe.parallel.intl.apk -o parallel_decoded
# Editar AndroidManifest.xml: mudar package name
apktool b parallel_decoded -o parallel_renamed.apk
zipalign -v 4 parallel_renamed.apk parallel_final.apk
apksigner sign --ks debug.keystore parallel_final.apk
adb install parallel_final.apk
```

Resultado: nenhum dos 24 packages na blacklist é encontrado. Tempo: ~15 minutos.

**Por que ainda funciona parcialmente:** maps patterns (`io.va`, `com.lbe.parallel`) verificam
a path da biblioteca nativa compilada — mais difícil de renomear do que o package manifest.
File artifacts em `/data/data/com.lbe.parallel.intl` persistem se o app original já foi instalado.

---

#### Ataque 2 — Android Work Profile (API oficial)

Apps como **Island** (Oasisfeng) usam Work Profile API nativa:

```
/data/user/0/com.incognia.guardapp  ← instância pessoal
/data/user/10/com.incognia.guardapp ← work profile (Island)
```

- `uid % 100_000` no perfil de trabalho = UID real do app, não offset
- Package é o do sistema, não está na blacklist
- `dataDir` fica em `/data/user/10/` — GuardApp **detecta** este caso ✓

---

#### Ataque 3 — App Virtualization Container

VMOS, F1VM e similares rodam o app dentro de um processo container:

```
UID 10xxx: container (VMOS)     ← UID % 100_000 < 100_000 ✓ (passa no check)
  └── processo virtualizado
      └── app alvo rodando "dentro" com UID do container
```

**Gap:** GuardApp não detecta virtualização de processo puro sem artifact files.

---

### 3.3 Frida / Hook Detection Bypass (mais crítico)

**O que o GuardApp verifica:**
- Socket TCP para `127.0.0.1:27042` (timeout 150ms)
- Parse `/proc/net/tcp` procurando port `0x699A` em LISTEN
- Arquivo `/data/local/tmp/frida-server`
- ClassLoader por XposedBridge
- `/proc/self/maps` com padrões `frida`, `xposed`, `substrate`

---

#### Ataque 1 — Porta customizada (trivial)

```bash
./frida-server -l 0.0.0.0:31337  # qualquer outra porta
frida -H 127.0.0.1:31337 -f com.incognia.guardapp ...
```

Port 27042 check → miss. `/proc/net/tcp` check → miss. Tempo: 10 segundos.

---

#### Ataque 2 — Unix Domain Socket (sem TCP)

```bash
./frida-server --listen unix:/tmp/frida.sock
```

Sem porta TCP, sem entrada em `/proc/net/tcp`. File artifact ainda detectado se
em `/data/local/tmp/frida-server` → mover para path não monitorada:

```bash
cp frida-server /data/app/com.someapp-xyz/lib/arm64/libhelper.so
./libhelper.so --listen unix:/tmp/frida.sock
```

---

#### Ataque 3 — Frida Gadget (o mais avançado, sem processo externo)

**Frida Gadget** é uma `.so` injetada no próprio APK — sem frida-server, sem porta:

```bash
# 1. Decompilar o APK alvo
apktool d guardapp.apk -o guardapp_mod

# 2. Injetar a library
cp frida-gadget-16.x.x-android-arm64.so guardapp_mod/lib/arm64-v8a/libgadget.so

# 3. Adicionar loadLibrary no smali do activity principal
#    Em MainActivity.smali, método <clinit>:
#      const-string v0, "gadget"
#      invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

# 4. Recompilar e assinar com CHAVE DO ATACANTE
apktool b guardapp_mod -o guardapp_patched.apk
zipalign -v 4 guardapp_patched.apk guardapp_aligned.apk
apksigner sign --ks attacker.keystore guardapp_aligned.apk
```

Resultado:
- Nenhum processo `frida-server` separado
- Port 27042 não abre
- `/proc/net/tcp` limpo
- Arquivo em `/data/app/...` (não em `/data/local/tmp/`)
- **SignatureAnalyzer detecta** via assinatura diferente — **mas só se `EXPECTED_CERT_SHA256 != ""`!**

---

#### Ataque 4 — Hookear o próprio detector em runtime

```javascript
Java.perform(function() {
    var SecurityReport = Java.use('com.incognia.guardapp.detection.SecurityReport');
    SecurityReport.getIsTampered.implementation = function() {
        console.log('[*] isTampered intercepted → false');
        return false;
    };
    SecurityReport.getRiskScore.implementation = function() { return 0; };
});
```

Para rodar isso antes da detecção: usar Frida Gadget (ataque 3) — carrega antes do Kotlin.

---

#### Ataque 5 — Native Hooking via PLT/GOT (sem Frida, invisível)

```c
// Substitui ponteiro de função na GOT diretamente
void* handle = dlopen("libguardapp.so", RTLD_NOW);
void** got_entry = (void**)dlsym(handle, "_ZN...EnvironmentGuard...generateReport...");
mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
*got_entry = &my_fake_generate_report;
```

**Completamente invisível** para checagens de arquivo, porta ou processo.

**Gaps atuais:**
- Porta 27042 hardcoded — trivialmente bypassada mudando a porta
- `/proc/net/tcp` bloqueado por SELinux no Android 10+ → checker ineficaz
- Sem detecção de Frida Gadget (injeção no APK)
- `EXPECTED_CERT_SHA256 = ""` → signature check inoperante em demo mode
- Sem **self-integrity check** — código em execução pode ter sido modificado

---

### 3.4 Root Detection Bypass

**O que o GuardApp verifica:**
- 9 paths para binário `su`
- 12 packages de root management
- `ro.debuggable=1`, `ro.secure=0`, `ro.build.type=eng|userdebug`
- `/system` writable

---

#### Ataque 1 — KernelSU / APatch (root de kernel, sem binário su)

KernelSU e APatch implementam root **no kernel**, sem:
- Binário `su` em paths monitoradas
- Processo `magiskd` no userspace
- Package detectável obrigatório

```bash
# KernelSU concede root via syscall interceptada no kernel
# Nenhum artifact userspace criado por padrão
```

---

#### Ataque 2 — Magisk Zygisk + DenyList

```
Magisk App → DenyList → adicionar "com.incognia.guardapp"
```

Quando GuardApp inicia:
- Zygisk detecta o app na DenyList
- **Remove os bind mounts** do Magisk antes do processo iniciar
- `/data/data/io.magisk.manager` não aparece para este processo
- Package Magisk não listado pelo PackageManager

---

#### Ataque 3 — Magisk Package Randomization

```
Magisk App → Configure → Randomize Package Name → "com.random.xyzabc123"
```

Nenhum dos 12 packages da blacklist é encontrado. Um clique, zero custo.

---

#### Ataque 4 — resetprop para mascarar propriedades perigosas

```bash
# Magisk module usa resetprop:
resetprop ro.debuggable 0
resetprop ro.secure 1
resetprop ro.build.type user
```

Visível para todos os processos, volátil entre reboots sem o módulo.

**Gaps atuais:**
- KernelSU/APatch não detectados
- Magisk DenyList bypassa completamente a verificação de package
- Sem análise de `/proc/self/mountinfo` (Magisk cria bind mounts detectáveis
  em processos **fora** da DenyList)
- Sem probe de `linkat()` syscall / anomalias de namespace

---

### 3.5 Signature Verification Bypass

**O que o GuardApp verifica:**
- X.509 subject contém "Android Debug"
- SHA-256 vs `EXPECTED_CERT_SHA256` (**vazio em demo mode!**)
- Installer source vs stores legítimas
- Consistência de package name

---

#### Ataque 1 — Demo Mode Explorado (crítico)

```kotlin
// SignatureAnalyzer.kt atual:
const val EXPECTED_CERT_SHA256 = ""  // ← VAZIO

// O guard:
if (EXPECTED_CERT_SHA256.isNotEmpty()) { ... }  // nunca executa
```

Qualquer APK reempacotado passa. O atacante pode assinar com qualquer chave.

---

#### Ataque 2 — Hookear PackageManager.getPackageInfo

```javascript
Java.perform(function() {
    var PackageManager = Java.use('android.app.ApplicationPackageManager');
    PackageManager.getPackageInfo
        .overload('java.lang.String', 'int')
        .implementation = function(packageName, flags) {
            var result = this.getPackageInfo(packageName, flags);
            if (packageName === 'com.incognia.guardapp' && (flags & 0x40) !== 0) {
                // result.signatures = [spoofed_signature];
            }
            return result;
        };
});
```

**Gaps atuais:**
- `EXPECTED_CERT_SHA256 = ""` → verificação de integridade desativada
- Sem verificação de signing scheme (v2/v3 obrigatório)
- O guarda mais forte (hash comparison) está explicitamente desligado

---

## 4. Ataques Além do Implementado

### 4.1 Debugger Attach (LLDB / ptrace)

Debuggers do sistema podem instrumentar sem rastros de Frida:

```bash
lldb
(lldb) process attach --pid <guardapp_pid>
(lldb) expr -- (void)NSLog(@"injected")
```

GuardApp **não detecta** debugger attach.

**Detecção via `/proc/self/status`:**
```kotlin
fun isBeingDebugged(): Boolean {
    return File("/proc/self/status").readLines()
        .firstOrNull { it.startsWith("TracerPid:") }
        ?.substringAfter(":")?.trim()?.toIntOrNull()
        ?.let { it != 0 } ?: false
}
```

---

### 4.2 APK Repackaging + Code Removal

```bash
jadx -d guardapp_decompiled guardapp-release.apk
# Abrir com Android Studio, remover todos os analyzers
# Recompilar como novo APK legítimo
```

R8/ProGuard full mode (já habilitado no release) dificulta — mas não impede — para um
engenheiro experiente. Mover lógica crítica para **JNI nativo** aumenta muito o custo.

---

### 4.3 Memory Patching via /proc/pid/mem (root required)

```python
pid = get_guardapp_pid()
mem = open(f'/proc/{pid}/mem', 'wb')
# ARM64: MOV X0, #0 (false) + RET
patch = bytes([0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6])
mem.seek(address_of_isTampered_method)
mem.write(patch)
```

Bypassa **absolutamente toda detecção em userspace**. Requer root.

---

### 4.4 Timing Side-Channel

GuardApp usa `async` + `awaitAll`. O atacante mede o tempo de resposta:

```
< 10ms  → checks terminaram sem detecções lentas
~150ms  → timeout do TCP probe ativou (Frida port check)
```

Revela quais verificações estão ativas sem necessidade de decompile.

---

### 4.5 Play Integrity API Bypass (quando implementada)

| Nível | Técnica | Custo |
|---|---|---|
| Básico | Magisk + Play Integrity Fix module | Baixo |
| Médio | ROM custom + GMS spoofado | Alto |
| Avançado | TEE key extraction (CVE-2023-21492 Samsung) | Muito alto |

---

### 4.6 IPC / Intent Attack

```kotlin
// App malicioso co-instalado observando comportamento do GuardApp
val intent = Intent().apply {
    component = ComponentName("com.incognia.guardapp", "...MainActivity")
}
startActivityForResult(intent, 0)
// Infer detection state via timing + response
```

---

## 5. Matriz de Gaps × Mitigações

| Gap | Severidade | Mitigação |
|---|---|---|
| `EXPECTED_CERT_SHA256 = ""` | 🔴 Crítico | Popular no CI/CD com hash real — nunca deixar vazio |
| Frida porta customizável | 🔴 Crítico | Detectar pelo nome do processo em `/proc`, não só porta |
| KernelSU / APatch | 🔴 Alto | Anomalias em `/proc/kallsyms`, `/sys/kernel/debug` |
| Magisk DenyList | 🔴 Alto | Play Integrity API attestation |
| Package renaming (clones) | 🟠 Alto | Comportamento + `/proc/self/maps` + UID (já implementado) |
| Build props spoofing | 🟠 Alto | Play Integrity + consistência cross-prop |
| Sem anti-debug | 🟠 Médio | `TracerPid` em `/proc/self/status` + ptrace self-check |
| Frida Gadget no APK | 🟠 Médio | `EXPECTED_CERT_SHA256` configurado + v2 scheme check |
| Sem self-integrity | 🟠 Médio | Checksums de classes críticas via JNI |
| `/proc/net/tcp` (SELinux) | 🟡 Médio | Remover ou mover para JNI; porta é mais confiável |
| APK repackaging | 🟡 Baixo | R8 full mode (já habilitado) + lógica crítica em nativo |

---

## 6. Kill Chain de um Atacante Profissional

```
RECONHECIMENTO
  1. jadx decompile → mapeou toda estrutura de detecção em < 1h
  2. Identificou: EXPECTED_CERT_SHA256 = "" → signature check inoperante
  3. Identificou: porta 27042 hardcoded → mudar para 31337

PREPARAÇÃO
  4. KernelSU instalado (sem binário su, sem package detectável)
  5. frida-server compilado na porta 31337
  6. Script Frida: Build props → valores Pixel 9, isTampered → false

EXECUÇÃO
  7. frida -H 127.0.0.1:31337 -f com.incognia.guardapp -l bypass.js

RESULTADO: riskScore=0, isTampered=false
Tempo total estimado por atacante experiente: 2–4 horas
```

---

## 7. Arquitetura de Defesa em Profundidade (o que falta)

```
┌─────────────────────────────────────────────────────────┐
│              DEFESA EM CAMADAS                          │
│                                                         │
│  Camada 1 — HARDWARE ATTESTATION (TEE)                  │
│  Play Integrity API → Google verifica o hardware        │
│  Resiste a: ROMs fake, Magisk, KernelSU                │
│                                                         │
│  Camada 2 — RUNTIME INTEGRITY (nativa)                  │
│  JNI checker, anti-debug ptrace, self-checksum          │
│  Resiste a: Frida Gadget, memory patching               │
│                                                         │
│  Camada 3 — SERVER-SIDE ANALYSIS                        │
│  Sinais enviados ao backend, verificação por ML         │
│  Fingerprint comportamental                             │
│  Resiste a: qualquer bypass local                       │
│  (atacante não controla o servidor)                     │
│                                                         │
│  Camada 4 — DETECÇÃO ATUAL (GuardApp ✓)                 │
│  Emulador, clone, hooks, root, assinatura               │
│  Resiste a: atacantes não sofisticados                  │
│                                                         │
│  PRINCÍPIO: cada camada falha de forma independente     │
│  Atacante precisa bypassar TODAS para ter sucesso       │
└─────────────────────────────────────────────────────────┘
```

### Play Integrity API (mais impactante que falta)

```kotlin
// build.gradle.kts:
// implementation("com.google.android.play:integrity:1.4.0")

suspend fun checkPlayIntegrity(context: Context): IntegrityVerdict {
    val manager = IntegrityManagerFactory.create(context)
    val nonce = Base64.getEncoder().encodeToString(
        ByteArray(16).also { SecureRandom().nextBytes(it) }
    )
    val token = manager.requestIntegrityToken(
        IntegrityTokenRequest.builder().setNonce(nonce).build()
    ).await()

    // CRÍTICO: verificar o token NO SERVIDOR — não no device
    // O device pode estar comprometido; o servidor não está
    return verifyOnServer(token.token())
}
```

### Native Anti-Debug (JNI)

```c
// guardapp_integrity.c
JNIEXPORT jboolean JNICALL
Java_com_incognia_guardapp_detection_NativeChecker_isBeingDebugged(
    JNIEnv* env, jclass cls) {

    // Check 1: TracerPid via /proc/self/status
    FILE* f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int tracer = atoi(line + 10);
                fclose(f);
                return tracer != 0 ? JNI_TRUE : JNI_FALSE;
            }
        }
        fclose(f);
    }

    // Check 2: ptrace self-attach falha se já há debugger
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) return JNI_TRUE;
    ptrace(PTRACE_DETACH, 0, NULL, NULL);

    return JNI_FALSE;
}
```

---

> **"Security is not a product, it's a process."** — Bruce Schneier
>
> Nenhuma detecção local é imperquebrável. O objetivo é aumentar o custo
> do atacante até que o retorno sobre o investimento seja negativo.
> O GuardApp já alcança isso para a grande maioria dos cenários de ameaça.
