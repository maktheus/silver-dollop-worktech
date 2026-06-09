# GuardApp — Roadmap de Implementação

> `[x]` = concluído | `[ ]` = pendente
>
> Fases 1–6 cobrem o escopo do desafio.
> Fase 7 é hardening para produção real.

---

## Fase 1 — Arquitetura Core

- [x] Definir enum `Severity` (LOW / MEDIUM / HIGH)
- [x] Definir enum `SignalCategory` (EMULATOR, CLONE_APP, VIRTUALIZATION, ROOT, SIGNATURE, SUSPICIOUS_PATH, SYSTEM_PROPERTY)
- [x] Criar data class `DetectionSignal(category, description, severity)`
- [x] Criar `fun interface EnvironmentAnalyzer` (SAM pattern para testabilidade)
- [x] Criar `SecurityReport(signals)` com propriedades `isTampered` e `riskScore`
- [x] Implementar `EnvironmentGuard` com facade paralela (`async` + `awaitAll` + `runCatching`)

---

## Fase 2 — Analyzers de Detecção

### EmulatorAnalyzer
- [x] Strategy 1 — `Build.*` fields (FINGERPRINT, MODEL, MANUFACTURER, HARDWARE, PRODUCT, BRAND)
- [x] Strategy 2 — `SystemProperties` reflection (`qemu.*`, `goldfish.*`)
- [x] Strategy 3 — QEMU file artifacts (`/dev/socket/qemud`, `/dev/qemu_pipe`, etc.)
- [x] Strategy 4 — `/proc/cpuinfo` probe (`intel`, `goldfish`)
- [x] Ofuscação de strings com `charArrayOf` (ex: `"goldfish"`)

### CloneAnalyzer
- [x] Strategy 1 — Package presence (24 packages conhecidos via PackageManager)
- [x] Strategy 2 — File artifacts (`/data/data/com.lbe.parallel.intl`, etc.)
- [x] Strategy 3 — Multi-user UID check (`uid / 100_000 != 0`)
- [x] Strategy 4 — Data directory redirect (fora de `/data/data/` ou `/data/user/0/`)
- [x] Strategy 5 — `/proc/self/maps` patterns (libs nativas de clone)
- [x] Constructor injection para testabilidade (`fileProbe`, `packageChecker`, `dataDirProvider`, `uidProvider`)

### VirtualizationAnalyzer
- [x] Hook file artifacts (Xposed, LSPosed, Frida, Substrate, Magisk)
- [x] `/proc/self/maps` patterns (`frida`, `xposed`, `substrate`, `va.hook`)
- [x] XposedBridge ClassLoader probe (`Class.forName`)
- [x] Frida port probe TCP `127.0.0.1:27042` (timeout 150ms)
- [x] `/proc/net/tcp` + `/proc/net/tcp6` parser (hex port `0x699A`, state `0A=LISTEN`)
- [x] Parser com teste isolado (sem dependência de filesystem real)

### RootDetector
- [x] 9 paths de binário `su`
- [x] 12 packages de root management (Magisk, SuperSU, KingRoot, etc.)
- [x] Propriedades perigosas (`ro.debuggable=1`, `ro.secure=0`, `ro.build.type=eng/userdebug`)
- [x] Partições de sistema writables (`/system`, `/system/bin`, `/vendor/bin`, etc.)
- [x] Constructor injection (`fileProbe`, `writableProbe`, `packageChecker`)

### SignatureAnalyzer
- [x] Debug certificate detection (X.509 subject "Android Debug")
- [x] SHA-256 comparison vs `EXPECTED_CERT_SHA256`
- [x] Installer source verification (Play, Galaxy Store, Huawei AppGallery, etc.)
- [x] Package name consistency (`applicationInfo.packageName` vs `context.packageName`)
- [x] Informational signal com hash atual (sempre emitido para diagnóstico)

---

## Fase 3 — Configuração Android

- [x] `AndroidManifest.xml` — bloco `<queries>` com todos os 24 packages clone + 12 root (Android 11+)
- [x] `AndroidManifest.xml` — permissão `INTERNET` para TCP probe
- [x] `AndroidManifest.xml` — `networkSecurityConfig` apontando para `network_security_config.xml`
- [x] `AndroidManifest.xml` — `android:allowBackup="false"`
- [x] `app/build.gradle.kts` — R8 (`isMinifyEnabled = true`) + shrink resources no release
- [x] `app/build.gradle.kts` — `proguardFiles` configurados
- [x] `app/build.gradle.kts` — `buildToolsVersion = "34.0.0"` (evitar AGP pegando 37.0.0)
- [x] `gradle.properties` — `android.useAndroidX`, `android.enableJetifier`
- [x] Compatibilidade AGP 8.9.2 + Gradle 8.11.1 + Android Studio 2025.3.4

---

## Fase 4 — UI / Apresentação

- [x] `MainActivity` com `lifecycleScope.launch` para não bloquear a Main thread
- [x] Exibição de sinais agrupados por severidade (HIGH → MEDIUM → LOW/informational)
- [x] Código de cores: vermelho (HIGH), laranja (MEDIUM), azul (LOW)
- [x] `riskScore` e status `isTampered` exibidos no topo

---

## Fase 5 — Testes Unitários

- [x] `EnvironmentGuardTest` — agregação de sinais de múltiplos analyzers
- [x] `EnvironmentGuardTest` — crash isolation (analyzer que lança não suprime os outros)
- [x] `EnvironmentGuardTest` — `isTampered` falso quando todos LOW
- [x] `EnvironmentGuardTest` — `riskScore` acumulado entre analyzers
- [x] `VirtualizationAnalyzerTest` — parser `/proc/net/tcp` true positives (loopback, wildcard)
- [x] `VirtualizationAnalyzerTest` — false positives (porta no remote address, estado ESTABLISHED)
- [x] `VirtualizationAnalyzerTest` — edge cases (lista vazia, linhas malformadas)
- [x] `CloneAnalyzerTest` — injeção de dependências para ambiente de clone simulado
- [x] `RootDetectorTest` — injeção de fileProbe/packageChecker para device rooteado simulado
- [x] `SecurityReportTest` — cálculo de `riskScore` e lógica de `isTampered`

---

## Fase 6 — Build, AVD e Validação de Cenários

- [x] AVD Pixel 10 Pro XL configurado (movido de C: para U: por espaço em disco)
- [x] Junction criada em `C:\Users\Samuel Ribeiro\.android\avd` → `U:\android\avd`
- [x] Emulador inicializado com sucesso
- [x] **Cenário B — Emulator Detection:** GuardApp detecta `sdk_gphone64_arm64`, `google_sdk_gphone64_arm64` e demais sinais de emulador
- [x] **Cenário C — Clone App Detection:** Parallel Space (`com.lbe.parallel.intl`) instalado e detectado com signal HIGH
- [x] **Cenário D — Frida Detection:** `frida-server` em `/data/local/tmp/` + `nc -l -p 27042` → GuardApp detecta arquivo artifact + porta em LISTEN
- [x] Documentação de arquitetura e decisões gerada (`docs/attack-research.md`)

---

## Fase 7 — Hardening para Produção (pós-desafio)

> Estas tarefas não são exigidas pelo desafio, mas são necessárias para
> um produto em produção real.

### Prioridade Crítica
- [x] **`SignatureAnalyzer`** — popular `EXPECTED_CERT_SHA256` com hash real do cert de release
  - Valor atual: SHA-256 do debug keystore (`androiddebugkey`) — `DE8964584DE8...`
  - Para produção: substituir pelo hash do cert de release via `apksigner verify --print-certs`
- [ ] **Play Integrity API** — integrar `com.google.android.play:integrity`
  - Verificar o token **no servidor**, nunca no device
  - Resiste a: ROMs fake, KernelSU, Magisk sem DenyList

### Prioridade Alta
- [x] **Extração de constantes** — `KNOWN_CLONE_PACKAGES`, `ROOT_PACKAGES`, `SU_PATHS`, `HOOK_PATHS` etc. movidos para `DetectionSignatures.kt`
- [ ] **Anti-debug** — checar `TracerPid` em `/proc/self/status` via Kotlin + ptrace self-check via JNI
- [ ] **KernelSU / APatch detection** — verificar anomalias em `/proc/kallsyms` (presença de símbolos `kernelsu_*`) e `/sys/kernel/debug`
- [ ] **Magisk bind mount detection** — analisar `/proc/self/mountinfo` para bind mounts suspeitos (Magisk monta sobre `/system` etc.)

### Prioridade Média
- [ ] **Frida nome de processo** — verificar `/proc/*/cmdline` por `frida-server` (port-agnostic)
- [ ] **Self-integrity nativa (JNI)** — checksum de classes críticas em C, injetável antes do runtime Kotlin
- [ ] **Verificação do signing scheme** — exigir APK Signature Scheme v2+ explicitamente
- [ ] **Remoção do `/proc/net/tcp` parser** — bloqueado por SELinux no Android 10+ para apps sem privilégio; substituir por JNI socket probe

### Prioridade Baixa
- [ ] **Server-side aggregation** — endpoint backend que recebe `SecurityReport` via HTTPS
  - Atacante controla o device mas não o servidor
  - Análise comportamental e histórica inviabiliza ataques locais
- [ ] **Behavioral detection** — detectar múltiplas instâncias do mesmo package via `/proc` scan
- [ ] **Consistência cross-prop** — validar combinações de `ro.hardware` + `ro.board.platform` + `ro.product.device` para detectar ROMs fake com props parcialmente spoofadas

---

## Decisão de Design: extrair constantes para arquivo separado?

**Status atual:** as listas (`KNOWN_CLONE_PACKAGES`, `ROOT_PACKAGES`, `SU_PATHS`, `HOOK_PATHS`) vivem em `private companion object` de cada analyzer.

**Para o desafio:** adequado. O escopo `private` é correto — cada analyzer é responsável pelas suas próprias assinaturas.

**Para produção:** sim, faz sentido extrair para `DetectionSignatures.kt`:

```kotlin
// detection/DetectionSignatures.kt
internal object DetectionSignatures {
    val KNOWN_CLONE_PACKAGES = listOf(...)
    val CLONE_ARTIFACT_PATHS = listOf(...)
    val CLONE_MAP_PATTERNS   = mapOf(...)
    val ROOT_PACKAGES        = listOf(...)
    val SU_PATHS             = listOf(...)
    val HOOK_PATHS           = listOf(...)
    // ...
}
```

Vantagens:
1. Atualização centralizada de assinaturas (sem navegar entre 4 arquivos)
2. Permite geração automática a partir de feed externo (threat intelligence)
3. Facilita testes de cobertura das listas

**Desvantagem:** expõe as listas entre analyzers (escopo `internal` vs `private`).
Mitigação: manter `internal` e não expor para fora do módulo `detection`.
