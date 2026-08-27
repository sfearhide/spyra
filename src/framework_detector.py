#!/usr/bin/env python3
"""
Framework Detector - identifies app frameworks and generates appropriate hooks
supports: React Native, Flutter, Unity, Xamarin, Cordova, and more.
"""

import re
import sys
import xml.etree.ElementTree as ET
from typing import Dict, List, Set, Optional
from dataclasses import dataclass
from pathlib import Path
from enum import Enum


class FrameworkType(Enum):
    NATIVE_JAVA = "native_java"
    NATIVE_KOTLIN = "native_kotlin"
    REACT_NATIVE = "react_native"
    FLUTTER = "flutter"
    UNITY = "unity"
    UNREAL = "unreal"
    XAMARIN = "xamarin"
    CORDOVA = "cordova"
    IONIC = "ionic"
    COCOS2DX = "cocos2dx"
    WEBVIEW_HYBRID = "webview_hybrid"
    NATIVE_CPP = "native_cpp"


@dataclass
class FrameworkSignature:
    name: str
    framework_type: FrameworkType
    indicators: Dict[str, List[str]]  # file_patterns, package_patterns, lib_patterns
    confidence: float = 0.0


class FrameworkDetector:
    FRAMEWORK_SIGNATURES = {
        FrameworkType.REACT_NATIVE: {
            "packages": [
                "com.facebook.react",
                "com.facebook.hermes",
                "com.facebook.jni",
                "com.facebook.soloader",
            ],
            "libraries": [
                "libreactnativejni.so",
                "libhermes.so",
                "libjscexecutor.so",
                "libfb.so",
                "libreact_nativemodule_core.so",
            ],
            "files": [
                "assets/index.android.bundle",
                "assets/index.bundle",
                "res/raw/index.android.bundle",
            ],
            "strings": ["React Native", "__fbBatchedBridge"],
        },
        FrameworkType.FLUTTER: {
            "packages": ["io.flutter", "io.flutter.embedding", "io.flutter.plugin"],
            "libraries": ["libflutter.so", "libapp.so"],
            "files": ["assets/flutter_assets", "lib/*/libflutter.so"],
            "strings": ["Flutter", "io.flutter"],
        },
        FrameworkType.UNITY: {
            "packages": ["com.unity3d", "com.unity.purchasing"],
            "libraries": ["libunity.so", "libmain.so", "libil2cpp.so"],
            "files": ["assets/bin/Data", "lib/*/libunity.so"],
            "strings": ["Unity", "UnityEngine"],
        },
        FrameworkType.XAMARIN: {
            "packages": ["mono.android", "xamarin.android", "mono.MonoRuntimeProvider"],
            "libraries": ["libmonodroid.so", "libmonosgen-2.0.so", "libxamarin-app.so"],
            "files": ["assemblies/*.dll"],
            "strings": ["Xamarin", "Mono.Android"],
        },
        FrameworkType.CORDOVA: {
            "packages": ["org.apache.cordova", "org.apache.cordova.CordovaActivity"],
            "libraries": [],
            "files": ["assets/www/cordova.js", "assets/www/index.html"],
            "strings": ["cordova", "Apache Cordova"],
        },
        FrameworkType.IONIC: {
            "packages": ["org.apache.cordova", "io.ionic"],
            "libraries": [],
            "files": ["assets/www/index.html", "assets/www/build/main.js"],
            "strings": ["ionic", "Ionic"],
        },
        FrameworkType.COCOS2DX: {
            "packages": ["org.cocos2dx"],
            "libraries": ["libcocos2d.so", "libcocos2dcpp.so"],
            "files": [],
            "strings": ["cocos2d", "Cocos2d-x"],
        },
        FrameworkType.UNREAL: {
            "packages": ["com.epicgames"],
            "libraries": ["libUE4.so", "libUnreal.so"],
            "files": [],
            "strings": ["Unreal", "UE4"],
        },
        FrameworkType.WEBVIEW_HYBRID: {
            "packages": ["com.android.webview", "com.google.android.webview"],
            "libraries": ["libwebviewchromium.so"],
            "files": [],
            "strings": ["android.webkit.WebView", "org.chromium.content.browser"],
        },
    }

    def __init__(self, decompiled_dir: Path):
        self.decompiled_dir = decompiled_dir
        self.detected_frameworks: List[FrameworkSignature] = []

    # detection threshold: lowered from 0.3 to 0.15 to avoid missing frameworks
    DETECTION_THRESHOLD = 0.15

    def detect_all(self) -> List[FrameworkSignature]:
        for framework_type, signatures in self.FRAMEWORK_SIGNATURES.items():
            confidence = self._calculate_confidence(framework_type, signatures)
            if confidence > self.DETECTION_THRESHOLD:
                sig = FrameworkSignature(
                    name=framework_type.value,
                    framework_type=framework_type,
                    indicators=signatures,
                    confidence=confidence,
                )
                self.detected_frameworks.append(sig)

        has_native_libs = self._has_native_code()

        if has_native_libs:
            self.detected_frameworks.append(
                FrameworkSignature(
                    name="native_cpp",
                    framework_type=FrameworkType.NATIVE_CPP,
                    indicators={},
                    confidence=1.0,
                )
            )

        has_cross_platform = any(
            f.framework_type not in (
                FrameworkType.NATIVE_JAVA,
                FrameworkType.NATIVE_KOTLIN,
                FrameworkType.NATIVE_CPP,
            )
            for f in self.detected_frameworks
        )

        is_kotlin = self._detect_kotlin()

        if is_kotlin:
            self.detected_frameworks.append(
                FrameworkSignature(
                    name="native_kotlin",
                    framework_type=FrameworkType.NATIVE_KOTLIN,
                    indicators={},
                    confidence=0.9 if not has_cross_platform else 0.5,
                )
            )
        else:
            self.detected_frameworks.append(
                FrameworkSignature(
                    name="native_java",
                    framework_type=FrameworkType.NATIVE_JAVA,
                    indicators={},
                    confidence=0.9 if not has_cross_platform else 0.5,
                )
            )

        # sort by confidence
        self.detected_frameworks.sort(key=lambda x: x.confidence, reverse=True)

        return self.detected_frameworks

    def _calculate_confidence(
        self, framework_type: FrameworkType, signatures: Dict
    ) -> float:
        score = 0.0
        max_score = 0.0

        if signatures.get("packages"):
            max_score += 0.4
            if self._check_packages(signatures["packages"]):
                score += 0.4
        if signatures.get("libraries"):
            max_score += 0.3
            found_libs = self._check_libraries(signatures["libraries"])
            score += 0.3 * (found_libs / len(signatures["libraries"]))
        if signatures.get("files"):
            max_score += 0.2
            if self._check_files(signatures["files"]):
                score += 0.2
        if signatures.get("strings"):
            max_score += 0.1
            if self._check_strings(signatures["strings"]):
                score += 0.1
        return score / max_score if max_score > 0 else 0.0

    def _check_packages(self, packages: List[str]) -> bool:
        for smali_dir in self.decompiled_dir.glob("smali*"):
            for package in packages:
                package_path = smali_dir / package.replace(".", "/")
                if package_path.exists():
                    return True
        return False

    def _check_libraries(self, libraries: List[str]) -> int:
        lib_dir = self.decompiled_dir / "lib"
        if not lib_dir.exists():
            return 0

        found = 0
        for lib in libraries:
            if list(lib_dir.rglob(lib)):
                found += 1
        return found

    def _check_files(self, files: List[str]) -> bool:
        for file_pattern in files:
            if list(self.decompiled_dir.glob(file_pattern)):
                return True
        return False

    def _check_strings(self, strings: List[str]) -> bool:
        for dex_file in self.decompiled_dir.parent.glob("*.dex"):
            try:
                dex_bytes = dex_file.read_bytes()
                dex_text = dex_bytes.decode("utf-8", errors="ignore")
                if any(s in dex_text for s in strings):
                    return True
            except Exception:
                continue

        # scan all smali files
        for smali_dir in self.decompiled_dir.glob("smali*"):
            for smali_file in smali_dir.rglob("*.smali"):
                try:
                    content = smali_file.read_text(encoding="utf-8", errors="ignore")
                    if any(s in content for s in strings):
                        return True
                except Exception:
                    continue
        return False

    def _has_native_code(self) -> bool:
        """Check for native C/C++ libraries (lib/*/*.so)."""
        lib_dir = self.decompiled_dir / "lib"
        if lib_dir.exists():
            if list(lib_dir.rglob("*.so")):
                return True
        return False

    def _detect_kotlin(self) -> bool:
        for smali_dir in self.decompiled_dir.glob("smali*"):
            kotlin_dir = smali_dir / "kotlin"
            if kotlin_dir.exists():
                return True

            metadata_file = smali_dir / "kotlin" / "Metadata.smali"
            if metadata_file.exists():
                return True

        meta_inf = self.decompiled_dir / "original" / "META-INF"
        if meta_inf.exists():
            if list(meta_inf.rglob("*.kotlin_module")):
                return True

        return False


class HookGenerator:
    BYPASS_SECTIONS = {
        "all": ("countermeasures", "spoofing"),
        "minimal": ("spoofing",),
        "none": (),
    }

    def __init__(self, frameworks: List[FrameworkSignature], bypass: str = "all"):
        if bypass not in self.BYPASS_SECTIONS:
            raise ValueError(
                f"unknown bypass tier {bypass!r} "
                f"(expected one of {sorted(self.BYPASS_SECTIONS)})"
            )
        self.frameworks = frameworks
        self.bypass = bypass

    def _wants(self, section: str) -> bool:
        return section in self.BYPASS_SECTIONS[self.bypass]

    def generate_hooks(self) -> tuple[str, bool]:
        fw_names = ", ".join(f.name for f in self.frameworks)

        script = (
            """// Auto-Generated hooks with resilient instrumentation
// compatible with Frida 17+

import Java from 'frida-java-bridge';

declare const Module: any;
declare const Interceptor: any;
declare const Process: any;
declare const Memory: any;
declare const send: any;
declare const console: any;
declare const setTimeout: any;
declare const setInterval: any;
declare const ptr: any;
declare const NULL: any;
declare const Stalker: any;
declare const DebugSymbol: any;
declare const Backtracer: any;
declare const Thread: any;
declare const rpc: any;
declare const NativeCallback: any;
declare const NativeFunction: any;

console.log('[*] Detected frameworks: """
            + fw_names
            + """');
"""
        )
        is_typescript = True

        script += self._generate_preamble()
        if self._wants("countermeasures"):
            script += self._generate_anti_detection_bypass()
        if self._wants("spoofing"):
            script += self._generate_environment_spoofing()

        # framework-specific hooks
        _baseline_hooks_added = False
        for framework in self.frameworks:
            if framework.framework_type == FrameworkType.REACT_NATIVE:
                script += self._generate_react_native_hooks()
            elif framework.framework_type == FrameworkType.FLUTTER:
                script += self._generate_flutter_hooks()
            elif framework.framework_type == FrameworkType.UNITY:
                script += self._generate_unity_hooks()
            elif framework.framework_type == FrameworkType.XAMARIN:
                script += self._generate_xamarin_hooks()
            elif framework.framework_type == FrameworkType.CORDOVA:
                script += self._generate_cordova_hooks()
            elif framework.framework_type == FrameworkType.WEBVIEW_HYBRID:
                script += self._generate_webview_hooks()
            elif framework.framework_type in (
                FrameworkType.NATIVE_JAVA,
                FrameworkType.NATIVE_KOTLIN,
                FrameworkType.NATIVE_CPP,
            ):
                if not _baseline_hooks_added:
                    script += self._generate_java_network_hooks()
                    script += self._generate_native_hooks()
                    script += self._generate_crypto_hooks()
                    script += self._generate_android_api_hooks()
                    _baseline_hooks_added = True

        if not _baseline_hooks_added:
            script += self._generate_java_network_hooks()
            script += self._generate_native_hooks()
            script += self._generate_crypto_hooks()
            script += self._generate_android_api_hooks()

        script += self._generate_modern_android_hooks()
        script += self._generate_abuse_primitive_hooks()
        script += self._generate_dlopen_watcher()
        script += self._generate_deferred_hooks()
        script = re.sub(r'(?<![a-zA-Z_])send\(', '_send(', script)

        return script, is_typescript

    def _generate_preamble(self) -> str:
        return """
Process.setExceptionHandler(function(details: any) {
    console.log('[!] Exception in ' + details.type + ' at ' + details.address +
                ' context: ' + JSON.stringify(details.context));
    return false;
});

const _fridaSend = send;
const _evtStats: any = {};

function _statEvent(type: any) {
    if (typeof type !== 'string') return;
    _evtStats[type] = (_evtStats[type] || 0) + 1;
}
const _hookStats: any = { java_installed: 0, native_installed: 0 };

function _send(payload: any, data?: any) {
    if (typeof payload === 'object' && payload !== null) {
        payload.thread_id = Process.getCurrentThreadId();
        if (payload.timestamp === undefined) payload.timestamp = Date.now();
        if ((data === undefined || data === null) && payload.type !== 'batch') _statEvent(payload.type);
    }
    _fridaSend(payload, data !== undefined ? data : null);
}

// convert a java byte[] to an ArrayBuffer for send(msg, data).
function javaBytesToAb(jbytes: any): ArrayBuffer {
    const len = jbytes.length;
    const ab = new ArrayBuffer(len);
    const u8 = new Uint8Array(ab);
    for (let i = 0; i < len; i++) u8[i] = jbytes[i] & 0xff;
    return ab;
}

// catches errors per-hook so one failing hook does not prevent others from installing
function safeJavaHook(className: string, methodName: string, hookFn: (cls: any) => void, optional?: boolean) {
    try {
        const cls = Java.use(className);
        hookFn(cls);
        _hookStats.java_installed++;
        console.log('[+] Hooked ' + className + '.' + methodName);
    } catch (e) {
        const errStr = '' + e;
        if (optional && errStr.indexOf('ClassNotFoundException') !== -1) {
            console.log('[~] ' + className + ' not present in this APK (optional, skipped)');
        } else {
            console.log('[-] Failed to hook ' + className + '.' + methodName + ': ' + e);
        }
    }
}

function hookAllOverloads(className: string, methodName: string, callback: (args: any[], method: string, overloadSig: string) => void) {
    try {
        const cls = Java.use(className);
        _hookedClasses[className] = (_hookedClasses[className] || 0) + 1;
        const method = cls[methodName];
        if (!method || !method.overloads) {
            console.log('[-] No overloads found for ' + className + '.' + methodName);
            return;
        }
        const overloads = method.overloads;
        for (let i = 0; i < overloads.length; i++) {
            const overload = overloads[i];
            const sig = overload.argumentTypes.map((t: any) => t.className).join(', ');
            overload.implementation = function() {
                const args = Array.prototype.slice.call(arguments);
                const fk = 'fired:' + className + '.' + methodName;
                _hookStats[fk] = (_hookStats[fk] || 0) + 1;
                try {
                    callback(args, methodName, sig);
                } catch (cbErr) {
                    // ...
                }
                return overload.apply(this, args);
            };
        }
        console.log('[+] Hooked all ' + overloads.length + ' overload(s) of ' + className + '.' + methodName);
    } catch (e) {
        console.log('[-] hookAllOverloads failed for ' + className + '.' + methodName + ': ' + e);
    }
}

function safeNativeHook(moduleName: string, funcName: string, callbacks: any) {
    try {
        const mod = Process.findModuleByName(moduleName);
        if (!mod) {
            return false;
        }
        
        const funcPtr = mod.findExportByName(funcName);
        if (!funcPtr) {
            return false;
        }
        
        const wrapped: any = {};
        const fk = 'fired:' + moduleName + '!' + funcName;
        if (callbacks.onEnter) {
            const origOnEnter = callbacks.onEnter;
            wrapped.onEnter = function() {
                _hookStats[fk] = (_hookStats[fk] || 0) + 1;
                return origOnEnter.apply(this, arguments);
            };
        } else {
            wrapped.onEnter = function() {
                _hookStats[fk] = (_hookStats[fk] || 0) + 1;
            };
        }
        
        if (callbacks.onLeave) wrapped.onLeave = callbacks.onLeave;
        Interceptor.attach(funcPtr, wrapped);
        _hookStats.native_installed++;
        console.log('[+] Native hook: ' + moduleName + '!' + funcName);
        
        return true;
    } catch (e) {
        console.log('[-] Native hook failed: ' + moduleName + '!' + funcName + ': ' + e);
        return false;
    }
}

function captureBacktrace(ctx: any): string[] {
    return [];
}

const _hookedNative: any = {};  // track which native funcs we already hooked
const _hookedClasses: any = {}; // track which Java classes we already hooked

const _ipcBuffer: any[] = [];
const IPC_FLUSH_MS = 100;
const IPC_MAX_SIZE = 40;
let _ipcFirstEvent = true;

function bufferedSend(evt: any) {
    evt.thread_id = Process.getCurrentThreadId();
    evt.timestamp = Date.now();
    _statEvent(evt.type);
    _ipcBuffer.push(evt);
    if (_ipcFirstEvent) {
        _ipcFirstEvent = false;
        flushIpcBuffer();
        return;
    }
    if (_ipcBuffer.length >= IPC_MAX_SIZE) flushIpcBuffer();
}

function flushIpcBuffer() {
    if (_ipcBuffer.length === 0) return;
    send({type: 'batch', events: _ipcBuffer.splice(0)});
}

setInterval(flushIpcBuffer, IPC_FLUSH_MS);
"""

    def _generate_anti_detection_bypass(self) -> str:
        return """
console.log('[*] Installing anti-termination hooks.');

Java.perform(() => {
    try {
        const _System = Java.use('java.lang.System');
        _System.exit.implementation = function(code: any) {
            console.log('[BYPASS] System.exit(' + code + ') blocked');
            send({type: 'bypass', action: 'system_exit', exit_code: code, timestamp: Date.now()});
        };
        console.log('[+] System.exit() blocked');
    } catch (e) {
        console.log('[-] System.exit hook: ' + e);
    }

    try {
        const _Runtime = Java.use('java.lang.Runtime');
        const exitOverloads = _Runtime.exit.overloads;
        for (let i = 0; i < exitOverloads.length; i++) {
            exitOverloads[i].implementation = function(code: any) {
                console.log('[BYPASS] Runtime.exit(' + code + ') blocked');
                send({type: 'bypass', action: 'runtime_exit', exit_code: code, timestamp: Date.now()});
            };
        }
        console.log('[+] Runtime.exit() blocked');
    } catch (e) {
        console.log('[-] Runtime.exit hook: ' + e);
    }

    try {
        const _Process = Java.use('android.os.Process');
        _Process.killProcess.implementation = function(pid: any) {
            const myPid = _Process.myPid();
            if (pid === myPid) {
                console.log('[BYPASS] Process.killProcess(self=' + pid + ') blocked');
                send({type: 'bypass', action: 'kill_self', pid: pid, timestamp: Date.now()});
                return;
            }
            _Process.killProcess.call(this, pid);
        };
        console.log('[+] Process.killProcess(self) blocked');
    } catch (e) {
        console.log('[-] Process.killProcess hook: ' + e);
    }

    try {
        const Activity = Java.use('android.app.Activity');
        const origFinish = Activity.finish.overloads;
        for (let i = 0; i < origFinish.length; i++) {
            const overload = origFinish[i];
            overload.implementation = function() {
                console.log('[LOGGED] Activity.finish()');
                bufferedSend({type: 'bypass', action: 'activity_finish', timestamp: Date.now()});
                return overload.apply(this, arguments);
            };
        }
        console.log('[+] Activity.finish() logged');
    } catch (e) {}

    try {
        const Activity = Java.use('android.app.Activity');
        if (Activity.finishAndRemoveTask) {
            const origFinishAndRemoveTask = Activity.finishAndRemoveTask.overloads;
            for (let i = 0; i < origFinishAndRemoveTask.length; i++) {
                const overload = origFinishAndRemoveTask[i];
                overload.implementation = function() {
                    console.log('[LOGGED] Activity.finishAndRemoveTask()');
                    bufferedSend({type: 'bypass', action: 'activity_finish_remove', timestamp: Date.now()});
                    return overload.apply(this, arguments);
                };
            }
        }
    } catch (e) {}

    try {
        const Activity = Java.use('android.app.Activity');
        if (Activity.finishAffinity) {
            const origFinishAffinity = Activity.finishAffinity.overloads;
            for (let i = 0; i < origFinishAffinity.length; i++) {
                const overload = origFinishAffinity[i];
                overload.implementation = function() {
                    console.log('[LOGGED] Activity.finishAffinity()');
                    bufferedSend({type: 'bypass', action: 'activity_finish_affinity', timestamp: Date.now()});
                    return overload.apply(this, arguments);
                };
            }
        }
    } catch (e) {}

    console.log('[+] Anti-termination hooks installed');
});

    try {
        const _libc = Process.findModuleByName('libc.so');
        if (_libc) {
            const _replacedAddrs: any = {};
            const exitFuncs = ['exit', '_exit', '_Exit'];
            for (const fn of exitFuncs) {
                const ptr = _libc.findExportByName(fn);
                if (ptr) {
                    const key = ptr.toString();
                    if (_replacedAddrs[key]) {
                        console.log('[~] Native ' + fn + ' shares address with previously replaced func, skipped');
                        continue;
                    }
                    _replacedAddrs[key] = true;
                    Interceptor.replace(ptr, new NativeCallback(function(code: number) {
                    console.log('[BYPASS] Native ' + fn + '(' + code + ') blocked');
                    send({type: 'bypass', action: 'native_exit', func: fn, exit_code: code, timestamp: Date.now()});
                    const _sleep = new NativeFunction(_libc!.findExportByName('sleep')!, 'uint32', ['uint32']);
                    while (true) { _sleep(3600); }
                }, 'void', ['int']));
                console.log('[+] Native ' + fn + '() blocked');
            }
        }
    }
} catch (e) {
    console.log('[-] Native exit hooks: ' + e);
}

try {
    const _libc2 = Process.findModuleByName('libc.so');
    if (_libc2) {
        const killPtr = _libc2.findExportByName('kill');
        if (killPtr) {
            const orig_kill = new NativeFunction(killPtr, 'int', ['int', 'int']);
            const getpidFn = new NativeFunction(_libc2.findExportByName('getpid')!, 'int', []);
            Interceptor.replace(killPtr, new NativeCallback(function(pid: number, sig: number): number {
                const myPid = getpidFn();
                if (pid === myPid || pid === 0 || pid === -myPid) {
                    console.log('[BYPASS] kill(pid=' + pid + ', sig=' + sig + ') self-kill blocked');
                    send({type: 'bypass', action: 'native_kill', pid: pid, signal: sig, timestamp: Date.now()});
                    return 0;
                }
                return orig_kill(pid, sig) as number;
            }, 'int', ['int', 'int']));
            console.log('[+] Native kill() self-kill blocked');
        }

        const tgkillPtr = _libc2.findExportByName('tgkill');
        if (tgkillPtr) {
            const orig_tgkill = new NativeFunction(tgkillPtr, 'int', ['int', 'int', 'int']);
            const getpidFn2 = new NativeFunction(_libc2.findExportByName('getpid')!, 'int', []);
            Interceptor.replace(tgkillPtr, new NativeCallback(function(tgid: number, tid: number, sig: number): number {
                const myPid = getpidFn2();
                if (tgid === myPid && (sig === 6 || sig === 9 || sig === 15)) {
                    console.log('[BYPASS] tgkill(tgid=' + tgid + ', tid=' + tid + ', sig=' + sig + ') blocked');
                    send({type: 'bypass', action: 'native_tgkill', tgid: tgid, tid: tid, signal: sig, timestamp: Date.now()});
                    return 0;
                }
                return orig_tgkill(tgid, tid, sig) as number;
            }, 'int', ['int', 'int', 'int']));
            console.log('[+] Native tgkill() blocked for fatal signals');
        }

        const abortPtr = _libc2.findExportByName('abort');
        if (abortPtr) {
            const _sleepFn = new NativeFunction(_libc2.findExportByName('sleep')!, 'uint32', ['uint32']);
            Interceptor.replace(abortPtr, new NativeCallback(function() {
                console.log('[BYPASS] abort() blocked');
                send({type: 'bypass', action: 'native_abort', timestamp: Date.now()});
                while (true) { _sleepFn(3600); }
            }, 'void', []));
            console.log('[+] Native abort() blocked');
        }
    }
} catch (e) {
    console.log('[-] Native kill/tgkill/abort hooks: ' + e);
}

console.log('[*] Installing anti-detection bypass.');
Java.perform(() => {
    setTimeout(() => {
    const rootIndicators = [
        '/system/app/Superuser.apk', '/sbin/su', '/system/bin/su',
        '/system/xbin/su', '/data/local/xbin/su', '/data/local/bin/su',
        '/system/sd/xbin/su', '/system/bin/failsafe/su', '/data/local/su',
        '/su/bin/su', '/data/adb/magisk', '/sbin/.magisk'
    ];

    safeJavaHook('java.io.File', 'exists', (cls: any) => {
        const origExists = cls.exists;
        cls.exists.implementation = function() {
            const path = this.getAbsolutePath();
            for (let i = 0; i < rootIndicators.length; i++) {
                if (path === rootIndicators[i]) {
                    console.log('[BYPASS] Root check blocked: ' + path);
                    send({type: 'bypass', action: 'root_check', path: path, timestamp: Date.now()});
                    return false;
                }
            }
            return origExists.call(this);
        };
    });

    // block "which su", "su", shell-based root checks
    hookAllOverloads('java.lang.Runtime', 'exec', (args: any[], method: string, sig: string) => {
        const cmd = args[0];
        const cmdStr = (typeof cmd === 'string') ? cmd : (cmd && cmd.toString ? cmd.toString() : '');
        if (cmdStr.indexOf('su') !== -1 || cmdStr.indexOf('which') !== -1 || cmdStr.indexOf('magisk') !== -1) {
            console.log('[BYPASS] exec blocked: ' + cmdStr);
            bufferedSend({type: 'bypass', action: 'exec_block', command: cmdStr, timestamp: Date.now()});
        }
        bufferedSend({type: 'exec', action: 'runtime_exec', command: cmdStr, backtrace: [], timestamp: Date.now()});
    });

    // apps detect frida by scanning /proc/self/maps for frida-agent, checking
    // default frida port 27042, or scanning for frida-server in process list.

    // NOTE: the old global BufferedReader.readLine frida-line filter was
    // removed: every line read by ANY stream had to enter the JS runtime,
    // which serialized all app I/O threads on the agent mutex and spun the
    // CPU (observed 4 threads at 100% -> ANR).  Maps-hiding is now handled
    // by the /proc/self/maps probe events instead.
    try {
        const CertificatePinner = Java.use('okhttp3.CertificatePinner');
        hookAllOverloads('okhttp3.CertificatePinner', 'check', (args: any[]) => {
            console.log('[BYPASS] OkHttp SSL pin bypassed for: ' + args[0]);
            send({type: 'bypass', action: 'ssl_pin_okhttp', host: '' + args[0], timestamp: Date.now()});
        });
    } catch (e) {}

    try {
        const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        const SSLContext = Java.use('javax.net.ssl.SSLContext');
        const TrustManagers = Java.array('javax.net.ssl.TrustManager', [
            Java.registerClass({
                name: 'com.spyra.TrustAllManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain: any, authType: any) {},
                    checkServerTrusted: function(chain: any, authType: any) {},
                    getAcceptedIssuers: function() { return []; }
                }
            }).$new()
        ]);

        hookAllOverloads('javax.net.ssl.SSLContext', 'init', (args: any[]) => {
            args[1] = TrustManagers;
            console.log('[BYPASS] SSLContext.init - injected permissive TrustManager');
            send({type: 'bypass', action: 'ssl_pin_context', timestamp: Date.now()});
        });
        console.log('[+] SSL pinning bypass');
    } catch (e) {
        console.log('[-] SSL pinning bypass: ' + e);
    }

    try {
        const NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityConfig');
        if (NetworkSecurityConfig.isCleartextTrafficPermitted) {
            const clearOverloads = NetworkSecurityConfig.isCleartextTrafficPermitted.overloads;
            for (let i = 0; i < clearOverloads.length; i++) {
                clearOverloads[i].implementation = function() {
                    return true;
                };
            }
            console.log('pass');
        }
    } catch (e) {}

    console.log('[+] Anti-detection bypass installed');
    }, 1000);
});
"""

    def _generate_environment_spoofing(self) -> str:
        # NOTE: deliberately Java-layer only.  Trapping __system_property_get
        # natively costs too much (property reads are extremely hot during
        # app startup and caused ANR-level CPU spins on the main thread).
        return """
console.log('[*] Installing environment spoofing.');
const SPOOFED_PROPS: any = {
    'ro.build.fingerprint': 'google/raven/raven:11/RQ1A.210105.003/user/release-keys',
    'ro.build.tags': 'release-keys',
    'ro.build.type': 'user',
    'ro.kernel.qemu': '0',
    'ro.hardware': 'qcom',
    'ro.product.model': 'Pixel 4',
    'ro.product.manufacturer': 'Google'
};

Java.perform(() => {
    try {
        const SP = Java.use('android.os.SystemProperties');
        SP.get.overload('java.lang.String').implementation = function(name: any) {
            const key = '' + name;
            if (Object.prototype.hasOwnProperty.call(SPOOFED_PROPS, key)) return SPOOFED_PROPS[key];
            return this.get(name);
        };
        SP.get.overload('java.lang.String', 'java.lang.String').implementation = function(name: any, def: any) {
            const key = '' + name;
            if (Object.prototype.hasOwnProperty.call(SPOOFED_PROPS, key)) return SPOOFED_PROPS[key];
            return this.get(name, def);
        };
        console.log('[+] SystemProperties.get spoofing active');
    } catch (e) {}
});
"""

    def _generate_abuse_primitive_hooks(self) -> str:
        return """
console.log('[*] Installing abuse-primitive hooks.');
Java.perform(() => {
    setTimeout(() => {
    // accessibility abuse — overlay attacks, UI automation fraud
    safeJavaHook('android.accessibilityservice.AccessibilityService', 'onAccessibilityEvent', (cls: any) => {
        hookAllOverloads('android.accessibilityservice.AccessibilityService', 'onAccessibilityEvent', (args: any[]) => {
            try {
                const e = args[0];
                bufferedSend({type: 'api', action: 'accessibility_event',
                    pkg: '' + (e.getPackageName() || ''), cls: '' + (e.getClassName() || ''),
                    timestamp: Date.now()});
            } catch (err) {}
        });
    }, true);

    // device admin activation (ransomware/lockware)
    safeJavaHook('android.app.admin.DeviceAdminReceiver', 'onEnabled', (cls: any) => {
        hookAllOverloads('android.app.admin.DeviceAdminReceiver', 'onEnabled', (args: any[]) => {
            bufferedSend({type: 'api', action: 'device_admin_enabled', timestamp: Date.now()});
        });
    }, true);

    // notification listening (OTP interception)
    safeJavaHook('android.service.notification.NotificationListenerService', 'onNotificationPosted', (cls: any) => {
        hookAllOverloads('android.service.notification.NotificationListenerService', 'onNotificationPosted', (args: any[]) => {
            try {
                const sbn = args[0];
                bufferedSend({type: 'api', action: 'notification_listen',
                    pkg: '' + (sbn.getPackageName() || ''), timestamp: Date.now()});
            } catch (err) {}
        });
    }, true);

    // job scheduling persistence
    safeJavaHook('android.app.job.JobScheduler', 'schedule', (cls: any) => {
        hookAllOverloads('android.app.job.JobScheduler', 'schedule', (args: any[]) => {
            try {
                let svc = '';
                try { svc = '' + args[0].getService().getClassName(); } catch (e2) {}
                bufferedSend({type: 'api', action: 'job_schedule', service: svc, timestamp: Date.now()});
            } catch (err) {}
        });
    }, true);

    // WorkManager persistence
    safeJavaHook('androidx.work.WorkManager', 'enqueue', (cls: any) => {
        hookAllOverloads('androidx.work.WorkManager', 'enqueue', (args: any[]) => {
            bufferedSend({type: 'api', action: 'work_enqueue', timestamp: Date.now()});
        });
    }, true);

    // JS bridge exposure
    safeJavaHook('android.webkit.WebView', 'addJavascriptInterface', (cls: any) => {
        hookAllOverloads('android.webkit.WebView', 'addJavascriptInterface', (args: any[]) => {
            try {
                bufferedSend({type: 'api', action: 'js_bridge_register', iface: '' + args[1], timestamp: Date.now()});
            } catch (err) {}
        });
    });

    // content provider exfil paths
    safeJavaHook('android.content.ContentResolver', 'openInputStream', (cls: any) => {
        hookAllOverloads('android.content.ContentResolver', 'openInputStream', (args: any[]) => {
            try {
                bufferedSend({type: 'api', action: 'content_open_input', uri: '' + args[0], timestamp: Date.now()});
            } catch (err) {}
        });
    });

    safeJavaHook('android.content.ContentResolver', 'openFileDescriptor', (cls: any) => {
        hookAllOverloads('android.content.ContentResolver', 'openFileDescriptor', (args: any[]) => {
            try {
                bufferedSend({type: 'api', action: 'content_open_fd', uri: '' + args[0], timestamp: Date.now()});
            } catch (err) {}
        });
    }, true);

    // package install sessions (dropper behavior)
    safeJavaHook('android.app.PackageInstaller$Session', 'commit', (cls: any) => {
        hookAllOverloads('android.app.PackageInstaller$Session', 'commit', (args: any[]) => {
            bufferedSend({type: 'api', action: 'package_install_commit', timestamp: Date.now()});
        });
    }, true);

    // cronet / grpc network stacks
    safeJavaHook('org.chromium.net.impl.CronetUrlRequest', 'start', (cls: any) => {
        hookAllOverloads('org.chromium.net.impl.CronetUrlRequest', 'start', (args: any[]) => {
            bufferedSend({type: 'network', action: 'cronet_request', timestamp: Date.now()});
        });
    }, true);

    safeJavaHook('io.grpc.stub.ClientCalls', 'enqueue', (cls: any) => {
        hookAllOverloads('io.grpc.stub.ClientCalls', 'enqueue', (args: any[]) => {
            bufferedSend({type: 'network', action: 'grpc_call', timestamp: Date.now()});
        });
    }, true);

    console.log('[+] Abuse-primitive hooks installed');
    }, 4000);
});
"""

    def _generate_react_native_hooks(self) -> str:
        return """
console.log('[*] Initializing React Native hooks.');
Java.perform(() => {
    try {
        const CatalystInstanceImpl = Java.use('com.facebook.react.bridge.CatalystInstanceImpl');
        CatalystInstanceImpl.jniCallJSFunction.implementation = function(module: any, method: any, args: any) {
            console.log(`[RN] JS Call: ${module}.${method}()`);
            send({type: 'react_native', action: 'js_call', module: module, method: method, timestamp: Date.now()});
            return this.jniCallJSFunction(module, method, args);
        };
        console.log('[+] CatalystInstanceImpl hooks');
    } catch (e) {
        console.log(`[-] CatalystInstanceImpl hooks: ${e}`);
    }

    try {
        const NativeModuleRegistry = Java.use('com.facebook.react.bridge.NativeModuleRegistry');
        NativeModuleRegistry.getModule.implementation = function(name: any) {
            console.log(`[RN] Native Module accessed: ${name}`);
            send({type: 'react_native', action: 'native_module', module: name, timestamp: Date.now()});
            return this.getModule(name);
        };
        console.log('[+] NativeModuleRegistry hooks');
    } catch (e) {
        console.log(`[-] NativeModuleRegistry hooks: ${e}`);
    }
});

const hermesLib = Module.findExportByName('libhermes.so', '_ZN6hermes2vm7Runtime6createERKNS0_12RuntimeConfigE');
if (hermesLib) {
    Interceptor.attach(hermesLib, {
        onEnter: function(args: any) {
            console.log('[RN] Hermes VM Runtime created');
            send({type: 'react_native', action: 'hermes_runtime_create', timestamp: Date.now()});
        }
    });
    console.log('[+] Hermes VM hooks');
} else {
    console.log('[-] Hermes VM not found (app may use JSC)');
}
"""

    def _generate_flutter_hooks(self) -> str:
        return """
console.log('[*] Initializing Flutter hooks.');
const flutterLib = Module.findExportByName('libflutter.so', '_ZN7flutter11DartIsolate10InitializeEv');
if (flutterLib) {
    Interceptor.attach(flutterLib, {
        onEnter: function(args) {
            console.log('[Flutter] Dart Isolate initialized');
            send({type: 'flutter', action: 'isolate_init'});
        }
    });
}
console.log('[*] Initializing Flutter hooks.');
Java.perform(() => {
    try {
        const MethodChannel = Java.use('io.flutter.plugin.common.MethodChannel');
        MethodChannel.invokeMethod.overload('java.lang.String', 'java.lang.Object').implementation = function(method, args) {
            console.log(`[Flutter] Method Channel: ${method}`);
            send({type: 'flutter', action: 'method_channel', method: method, args: args});
            return this.invokeMethod(method, args);
        };
        console.log('[✓] Flutter hooks');
    } catch (e) {
        console.log(`[-] Flutter hooks error: ${e}`);
    }
});
"""

    def _generate_unity_hooks(self) -> str:
        return """
console.log('[*] Initializing Unity hooks.');
const unityLib = Process.findModuleByName('libunity.so');
if (unityLib) {
    const il2cppInit = Module.findExportByName('libil2cpp.so', 'il2cpp_init');
    if (il2cppInit) {
        Interceptor.attach(il2cppInit, {
            onEnter: function(args) {
                console.log('[Unity] IL2CPP initialized');
                send({type: 'unity', action: 'il2cpp_init'});
            }
        });
    }
    const playerLoop = Module.findExportByName('libunity.so', '_ZN5Unity11PlayerLoop7RunLoopEv');
    if (playerLoop) {
        console.log('[Unity] Player loop hooked');
    }
}
Java.perform(() => {
    try {
        const UnityPlayer = Java.use('com.unity3d.player.UnityPlayer');
        UnityPlayer.UnitySendMessage.implementation = function(gameObject, method, message) {
            console.log(`[Unity] SendMessage: ${gameObject}.${method}(${message})`);
            send({type: 'unity', action: 'send_message', object: gameObject, method: method});
            return this.UnitySendMessage(gameObject, method, message);
        };
        console.log('[✓] Unity hooks');
    } catch (e) {
        console.log(`[-] Unity hooks error: ${e}`);
    }
});
"""

    def _generate_xamarin_hooks(self) -> str:
        return """
console.log('[*] Initializing Xamarin hooks.');
Java.perform(() => {
    try {
        const MonoRuntime = Java.use('mono.MonoRuntimeProvider');
        console.log('[Xamarin] Mono runtime detected');

        const Assembly = Java.use('mono.android.Runtime');
        console.log('[✓] Xamarin hooks');
    } catch (e) {
        console.log(`[-] Xamarin hooks error: ${e}`);
    }
});
const monoLib = Module.findExportByName('libmonosgen-2.0.so', 'mono_jit_init_version');
if (monoLib) {
    Interceptor.attach(monoLib, {
        onEnter: function(args) {
            console.log('[Xamarin] Mono JIT initialized');
            send({type: 'xamarin', action: 'mono_init'});
        }
    });
}
"""

    def _generate_cordova_hooks(self) -> str:
        return """
console.log('[*] Initializing Cordova hooks.');
Java.perform(() => {
    try {
        const CordovaWebView = Java.use('org.apache.cordova.CordovaWebView');
        const CordovaPlugin = Java.use('org.apache.cordova.CordovaPlugin');
        
        CordovaPlugin.execute.implementation = function(action, args, callbackContext) {
            console.log(`[Cordova] Plugin execute: ${action}`);
            send({type: 'cordova', action: 'plugin_execute', plugin_action: action});
            return this.execute(action, args, callbackContext);
        };
        
        console.log('[✓] Cordova hooks');
    } catch (e) {
        console.log(`[-] Cordova hooks error: ${e}`);
    }
});
"""

    def _generate_webview_hooks(self) -> str:
        return """
console.log('[*] Initializing WebView hooks.');
Java.perform(() => {
    try {
        const WebView = Java.use('android.webkit.WebView');
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log(`[WebView] Loading URL: ${url}`);
            send({type: 'network', action: 'webview_load', url: url, timestamp: Date.now()});
            return this.loadUrl(url);
        };
        
        const WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.shouldInterceptRequest.overload('android.webkit.WebView', 'java.lang.String').implementation = function(view, url) {
            console.log(`[WebView] Intercept Request: ${url}`);
            send({type: 'network', action: 'webview_intercept', url: url, timestamp: Date.now()});
            return this.shouldInterceptRequest(view, url);
        };

        console.log('[✓] WebView hooks');
    } catch (e) {
        console.log(`[-] WebView hooks error: ${e}`);
    }
});
"""

    def _generate_crypto_hooks(self) -> str:
        return """
console.log('[*] Installing Crypto hooks.');
Java.perform(() => { 
    setTimeout(() => {
    hookAllOverloads('javax.crypto.Cipher', 'doFinal', (args: any[], method: string, sig: string) => {
        try {
            bufferedSend({type: 'crypto', action: 'cipher_dofinal', overload: sig, timestamp: Date.now()});
        } catch (e) {}
    });

    hookAllOverloads('javax.crypto.Cipher', 'getInstance', (args: any[], method: string, sig: string) => {
        try {
            const transformation = '' + args[0];
            bufferedSend({type: 'crypto', action: 'cipher_getinstance', transformation: transformation, timestamp: Date.now()});
        } catch (e) {}
    });

    hookAllOverloads('java.security.MessageDigest', 'digest', (args: any[], method: string, sig: string) => {
        try {
            bufferedSend({type: 'crypto', action: 'digest', overload: sig, timestamp: Date.now()});
        } catch (e) {}
    });

    hookAllOverloads('java.security.MessageDigest', 'getInstance', (args: any[], method: string, sig: string) => {
        try {
            const algo = '' + args[0];
            bufferedSend({type: 'crypto', action: 'digest_getinstance', algorithm: algo, timestamp: Date.now()});
        } catch (e) {}
    });

    // captures encryption keys being created
    hookAllOverloads('javax.crypto.spec.SecretKeySpec', '$init', (args: any[], method: string, sig: string) => {
        try {
            const algo = '' + args[1];
            bufferedSend({type: 'crypto', action: 'secret_key', algorithm: algo, timestamp: Date.now()});
        } catch (e) {}
    });

    hookAllOverloads('javax.crypto.KeyGenerator', 'getInstance', (args: any[], method: string, sig: string) => {
        try {
            const algo = '' + args[0];
            bufferedSend({type: 'crypto', action: 'keygen', algorithm: algo, timestamp: Date.now()});
        } catch (e) {}
    });

    console.log('[+] Crypto hooks');
    }, 2500);
});
"""

    def _generate_android_api_hooks(self) -> str:
        return """
console.log('[*] Installing Android API hooks.');
Java.perform(() => {
    setTimeout(() => {
    hookAllOverloads('android.telephony.SmsManager', 'sendTextMessage', (args: any[]) => {
        const dest = '' + args[0];
        const text = '' + args[2];
        console.log('[SMS] Sending to ' + dest + ': ' + text);
        send({type: 'api', action: 'sms_send', dest: dest, text: text, timestamp: Date.now()});
    });

    hookAllOverloads('android.telephony.SmsManager', 'sendMultipartTextMessage', (args: any[]) => {
        const dest = '' + args[0];
        console.log('[SMS] Multipart SMS to ' + dest);
        send({type: 'api', action: 'sms_send_multipart', dest: dest, timestamp: Date.now()});
    });

    hookAllOverloads('android.telephony.SmsManager', 'sendDataMessage', (args: any[]) => {
        const dest = '' + args[0];
        console.log('[SMS] Data SMS to ' + dest);
        send({type: 'api', action: 'sms_send_data', dest: dest, timestamp: Date.now()});
    });

    hookAllOverloads('android.location.LocationManager', 'getLastKnownLocation', (args: any[]) => {
        const provider = '' + args[0];
        console.log('[Location] getLastKnownLocation(' + provider + ')');
        send({type: 'api', action: 'location_get', provider: provider, timestamp: Date.now()});
    });

    hookAllOverloads('android.location.LocationManager', 'requestLocationUpdates', (args: any[]) => {
        console.log('[Location] requestLocationUpdates()');
        send({type: 'api', action: 'location_updates', timestamp: Date.now()});
    });

    // pkg enumeration
    hookAllOverloads('android.app.ApplicationPackageManager', 'getInstalledPackages', (args: any[]) => {
        console.log('[API] getInstalledPackages()');
        send({type: 'api', action: 'package_list', timestamp: Date.now()});
    });

    hookAllOverloads('android.app.ApplicationPackageManager', 'getInstalledApplications', (args: any[]) => {
        console.log('[API] getInstalledApplications()');
        send({type: 'api', action: 'app_list', timestamp: Date.now()});
    });

    hookAllOverloads('android.telephony.TelephonyManager', 'getDeviceId', (args: any[]) => {
        console.log('[SYSTEM] getDeviceId()');
        send({type: 'system', action: 'get_device_id', timestamp: Date.now()});
    });

    hookAllOverloads('android.telephony.TelephonyManager', 'getImei', (args: any[]) => {
        console.log('[SYSTEM] getImei()');
        send({type: 'system', action: 'get_imei', timestamp: Date.now()});
    });

    hookAllOverloads('android.telephony.TelephonyManager', 'getSubscriberId', (args: any[]) => {
        console.log('[SYSTEM] getSubscriberId() (IMSI)');
        send({type: 'system', action: 'get_imsi', timestamp: Date.now()});
    });

    hookAllOverloads('android.telephony.TelephonyManager', 'getLine1Number', (args: any[]) => {
        console.log('[SYSTEM] getLine1Number() (phone number)');
        send({type: 'system', action: 'get_phone_number', timestamp: Date.now()});
    });

    hookAllOverloads('android.telephony.TelephonyManager', 'getSimSerialNumber', (args: any[]) => {
        console.log('[SYSTEM] getSimSerialNumber()');
        send({type: 'system', action: 'get_sim_serial', timestamp: Date.now()});
    });

    hookAllOverloads('android.net.wifi.WifiInfo', 'getMacAddress', (args: any[]) => {
        console.log('[SYSTEM] WifiInfo.getMacAddress()');
        send({type: 'system', action: 'get_mac_address', timestamp: Date.now()});
    });

    // data theft
    hookAllOverloads('android.provider.ContactsContract$Contacts', 'getLookupUri', (args: any[]) => {
        console.log('[API] ContactsContract access');
        send({type: 'api', action: 'contacts_access', timestamp: Date.now()});
    });
    }, 3000);
});
"""

    def _generate_java_network_hooks(self) -> str:
        return """
console.log('[*] Installing Java network hooks.');
Java.perform(() => {
    setTimeout(() => {
    hookAllOverloads('java.net.HttpURLConnection', 'getInputStream', (args: any[]) => {
        send({type: 'network', action: 'http_request', timestamp: Date.now()});
    });

    safeJavaHook('com.android.okhttp.internal.huc.HttpURLConnectionImpl', 'getInputStream', (cls: any) => {
        const overloads = cls.getInputStream.overloads;
        for (let i = 0; i < overloads.length; i++) {
            const overload = overloads[i];
            overload.implementation = function() {
                try {
                    const url = this.getURL().toString();
                    const method = this.getRequestMethod();
                    console.log('[HTTP] ' + method + ' ' + url);
                    send({type: 'network', action: 'http_request', method: method, url: url, timestamp: Date.now()});
                } catch (e) {}
                return overload.call(this);
            };
        }
    });

    safeJavaHook('com.android.okhttp.internal.huc.HttpURLConnectionImpl', 'getOutputStream', (cls: any) => {
        const overloads = cls.getOutputStream.overloads;
        for (let i = 0; i < overloads.length; i++) {
            const overload = overloads[i];
            overload.implementation = function() {
                try {
                    const url = this.getURL().toString();
                    const method = this.getRequestMethod();
                    console.log('[HTTP] ' + method + ' ' + url + ' (body)');
                    send({type: 'network', action: 'http_request_body', method: method, url: url, timestamp: Date.now()});
                } catch (e) {}
                return overload.call(this);
            };
        }
    });

    // HttpsURLConnection
    safeJavaHook('javax.net.ssl.HttpsURLConnection', 'getInputStream', (cls: any) => {
        const overloads = cls.getInputStream.overloads;
        for (let i = 0; i < overloads.length; i++) {
            const overload = overloads[i];
            overload.implementation = function() {
                try {
                    const url = this.getURL().toString();
                    const method = this.getRequestMethod();
                    console.log('[HTTPS] ' + method + ' ' + url);
                    send({type: 'network', action: 'https_request', method: method, url: url, timestamp: Date.now()});
                } catch (e) {}
                return overload.call(this);
            };
        }
    });

    safeJavaHook('okhttp3.OkHttpClient', 'newCall', (cls: any) => {
        const overloads = cls.newCall.overloads;
        for (let i = 0; i < overloads.length; i++) {
            const overload = overloads[i];
            overload.implementation = function() {
                try {
                    const request = arguments[0];
                    const url = request.url().toString();
                    const method = request.method();
                    console.log('[OKHTTP] ' + method + ' ' + url);
                    send({type: 'network', action: 'okhttp_request', method: method, url: url, timestamp: Date.now()});
                } catch (e) {}
                return overload.apply(this, arguments);
            };
        }
    }, true);

    // OkHttp3 response body — also optional (see above)
    safeJavaHook('okhttp3.ResponseBody', 'string', (cls: any) => {
        const overloads = cls.string.overloads;
        for (let i = 0; i < overloads.length; i++) {
            const overload = overloads[i];
            overload.implementation = function() {
                const body = overload.call(this);
                try {
                    const preview = body.length > 500 ? body.substring(0, 500) + '...' : body;
                    send({type: 'network', action: 'okhttp_response', body: preview, size: body.length, timestamp: Date.now()});
                } catch (e) {}
                return body;
            };
        }
    }, true);

    hookAllOverloads('java.net.Socket', '$init', (args: any[]) => {
        try {
            if (args.length >= 2) {
                const host = '' + args[0];
                const port = args[1];
                bufferedSend({type: 'network', action: 'socket_connect', host: host, port: '' + port, timestamp: Date.now()});
            }
        } catch (e) {}
    });

    // DNS-over-HTTPS (DoH) endpoint list for detection
    const DOH_ENDPOINTS = [
        'dns.google', 'dns.google.com', 'cloudflare-dns.com',
        '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4',
        'dns.quad9.net', 'doh.opendns.com', 'dns.adguard.com'
    ];

    hookAllOverloads('java.net.URL', '$init', (args: any[]) => {
        try {
            if (args.length >= 1) {
                const url = '' + args[0];
                bufferedSend({type: 'network', action: 'url_init', url: url, timestamp: Date.now()});

                for (const endpoint of DOH_ENDPOINTS) {
                    if (url.indexOf(endpoint) !== -1 &&
                        (url.indexOf('/dns-query') !== -1 || url.indexOf('/resolve') !== -1)) {
                        console.log('[!!! DoH] DNS-over-HTTPS detected: ' + url);
                        bufferedSend({type: 'network', action: 'doh_request', url: url,
                              endpoint: endpoint, timestamp: Date.now()});
                        break;
                    }
                }
            }
        } catch (e) {}
    });

    console.log('[+] Java network hooks');
    }, 2000);
});
"""

    def _generate_native_hooks(self) -> str:
        return """
console.log('[*] Installing native hooks.');

// T-fix: never instrument the instrumentation.  Any libc call whose return
// address lands inside the frida-agent module is the agent's OWN business
// (its JIT compiles JS -> mmap/mprotect PROT_EXEC -> our hooks -> more JS:
// a feedback loop that spun 4 app threads at 100%% CPU inside sched_yield).
const _fridaModuleRange: any = (function() {
    try {
        for (const m of Process.enumerateModules()) {
            if (m.name.indexOf('frida') !== -1 || m.name.indexOf('gadget') !== -1) {
                return { base: m.base, end: m.base.add(m.size) };
            }
        }
    } catch (e) {}
    return null;
})();
function _isFridaInternal(this: any): boolean {
    try {
        const ra = this.returnAddress;
        if (ra === undefined || ra === null || _fridaModuleRange === null) return false;
        return ra.compare(_fridaModuleRange.base) >= 0 && ra.compare(_fridaModuleRange.end) < 0;
    } catch (e) { return false; }
}

const libc = Process.getModuleByName('libc.so');
if (libc) {
    const file_funcs = ['fopen', 'open'];
    for (const funcName of file_funcs) {
        const funcPtr = libc.findExportByName(funcName);
        if (funcPtr) {
            Interceptor.attach(funcPtr, {
                onEnter: function(args: any) {
                    try {
                        const path = args[0].readUtf8String();
                        if (!path) return;
                        // filter /dev/ and /sys/ (pure noise)
                        if (path.includes('/dev/') || path.includes('/sys/')) return;

                        if (path.includes('/proc/')) {
                            bufferedSend({
                                type: 'native', func: funcName, path: path,
                                action: 'proc_probe',
                                is_maps: path.includes('/proc/self/maps'),
                                is_net: path.includes('/proc/net/'),
                                is_status: path.includes('/proc/self/status'),
                                timestamp: Date.now()
                            });
                        } else {
                            bufferedSend({type: 'native', func: funcName, path: path, timestamp: Date.now()});
                        }
                    } catch (e) {}
                }
            });
        }
    }

    // T11: openat watcher DISABLED — ART uses openat on nearly every I/O;
    // trapping it caused main-thread CPU spin (ANR) on low-end emulators.
    // Re-enable only with sampling (e.g. every Nth call).
    const _openatWatch = false;
    if (_openatWatch) {
        const openatPtr = libc.findExportByName('openat');
        if (openatPtr) {
            Interceptor.attach(openatPtr, {
                onEnter: function(args: any) {
                    try {
                        const path = args[1].readUtf8String();
                        if (!path || path.includes('/dev/') || path.includes('/sys/')) return;
                        if (path.includes('/proc/')) {
                            bufferedSend({
                                type: 'native', func: 'openat', path: path,
                                action: 'proc_probe',
                                is_maps: path.includes('/proc/self/maps'),
                                is_net: path.includes('/proc/net/'),
                                is_status: path.includes('/proc/self/status'),
                                timestamp: Date.now()
                            });
                        } else {
                            bufferedSend({type: 'native', func: 'openat', path: path, timestamp: Date.now()});
                        }
                    } catch (e) {}
                }
            });
            console.log('[+] openat watcher');
        }
    }

    // T11: memfd_create — anonymous executable memory artifacts
    const memfdPtr = libc.findExportByName('memfd_create');
    if (memfdPtr) {
        Interceptor.attach(memfdPtr, {
            onEnter: function(args: any) {
                try {
                    const name = args[0].readUtf8String();
                    bufferedSend({type: 'native', action: 'memfd_create', name: name, timestamp: Date.now()});
                    console.log('[!!! MEMFD] memfd_create("' + name + '")');
                } catch (e) {}
            }
        });
    }

    // T11: process_vm_readv — cross-process memory reading/injection
    const pvrPtr = libc.findExportByName('process_vm_readv');
    if (pvrPtr) {
        Interceptor.attach(pvrPtr, {
            onEnter: function(args: any) {
                try {
                    bufferedSend({type: 'native', action: 'process_vm_readv',
                        target_pid: args[0].toInt32(), timestamp: Date.now()});
                    console.log('[!!! PVM] process_vm_readv(pid=' + args[0].toInt32() + ')');
                } catch (e) {}
            }
        });
    }

    // dns hooks — T9: resolved addresses feed an ip->host map so raw
    // connect() events can be attributed to hostnames
    const _ipHost: any = {};
    function _rememberAddr(sa: any, family: number, host: string | null) {
        if (family === 2) { // AF_INET
            const ip = sa.add(4).readU8() + '.' + sa.add(5).readU8() + '.' +
                       sa.add(6).readU8() + '.' + sa.add(7).readU8();
            _ipHost[ip] = host;
        } else if (family === 10) { // AF_INET6 (same group format as connect())
            let ip = "";
            for (let i = 0; i < 16; i += 2) {
                if (i > 0) ip += ":";
                ip += ((sa.add(8 + i).readU8() << 8) | sa.add(9 + i).readU8()).toString(16);
            }
            _ipHost[ip] = host;
        }
    }

    const getaddrinfoPtr = libc.findExportByName('getaddrinfo');
    if (getaddrinfoPtr) {
        Interceptor.attach(getaddrinfoPtr, {
            onEnter: function(args: any) {
                try {
                    this._host = args[0].readUtf8String();
                    if (this._host) {
                        console.log('[DNS] getaddrinfo: ' + this._host);
                        bufferedSend({type: 'network', action: 'dns_resolve', host: this._host, timestamp: Date.now()});
                    }
                } catch (e) {}
            },
            onLeave: function(retval: any) {
                try {
                    if (!this._host || retval.isNull()) return;
                    // struct addrinfo walk (bionic): ai_family@4, ai_addr, ai_next
                    const ps = Process.pointerSize;
                    const offAddr = ps === 8 ? 24 : 20;
                    const offNext = ps === 8 ? 40 : 28;
                    let ai = retval;
                    let n = 0;
                    while (!ai.isNull() && n < 8) {
                        try {
                            const family = ai.add(4).readS32();
                            const sa = ai.add(offAddr).readPointer();
                            if (!sa.isNull()) _rememberAddr(sa, family, this._host);
                        } catch (inner) {}
                        ai = ai.add(offNext).readPointer();
                        n++;
                    }
                } catch (e) {}
            }
        });
    }
    const gethostbynamePtr = libc.findExportByName('gethostbyname');
    if (gethostbynamePtr) {
        Interceptor.attach(gethostbynamePtr, {
            onEnter: function(args: any) {
                try {
                    const host = args[0].readUtf8String();
                    if (host) {
                        console.log('[DNS] gethostbyname: ' + host);
                        bufferedSend({type: 'network', action: 'dns_resolve', host: host, timestamp: Date.now()});
                    }
                } catch (e) {}
            }
        });
    }

    const connectPtr = libc.findExportByName('connect');
    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onEnter: function(args: any) {
                if (_isFridaInternal.call(this)) return;
                this.sock = args[0].toInt32();
                const sockaddr = args[1];
                const socklen = args[2].toInt32();
                try {
                    const family = sockaddr.readU16();
                    if (family === 2) { // AF_INET
                        const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                        const ip = sockaddr.add(4).readU8() + '.' + sockaddr.add(5).readU8() + '.' + sockaddr.add(6).readU8() + '.' + sockaddr.add(7).readU8();
                        console.log(`[native] connect(${ip}:${port})`);
                        const bt = captureBacktrace(this.context);
                        bufferedSend({type: 'network', action: 'connect', ip: ip, port: port, host: _ipHost[ip] || null, backtrace: bt, timestamp: Date.now()});
                    } else if (family === 10) { // AF_INET6
                        const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                        let ip = "";
                        for (let i = 0; i < 16; i += 2) {
                            const b1 = sockaddr.add(8 + i).readU8();
                            const b2 = sockaddr.add(8 + i + 1).readU8();
                            if (i > 0) ip += ":";
                            ip += ((b1 << 8) | b2).toString(16);
                        }
                        console.log(`[native] connect([${ip}]:${port})`);
                        const bt = captureBacktrace(this.context);
                        bufferedSend({type: 'network', action: 'connect', ip: ip, port: port, host: _ipHost[ip] || null, backtrace: bt, timestamp: Date.now()});
                    }
                } catch (e) {}
            }
        });
    }

    // Log byte counts only — hex-encoding 128 bytes per call on every send/recv
    // is extremely expensive on hot-path sockets (WebView IPC alone can fire
    // thousands of times per second) and was a major ANR contributor.
    // Rate-limit to one event per 500ms per direction to avoid flooding the IPC
    // queue and blocking the UI thread.
    let _lastSendEvt = 0;
    let _lastRecvEvt = 0;
    const NET_SAMPLE_MS = 500;

    const net_send_funcs = ['send', 'sendto'];
    for (const funcName of net_send_funcs) {
        const funcPtr = libc.findExportByName(funcName);
        if (funcPtr) {
            Interceptor.attach(funcPtr, {
                onEnter: function(args: any) {
                    if (_isFridaInternal.call(this)) return;
                    try {
                        const now = Date.now();
                        if (now - _lastSendEvt < NET_SAMPLE_MS) return;
                        _lastSendEvt = now;
                        const len = args[2].toInt32();
                        bufferedSend({type: 'network', action: funcName, bytes: len,
                            timestamp: now});
                    } catch (e) {}
                }
            });
        }
    }
    const net_recv_funcs = ['recv', 'recvfrom'];
    for (const funcName of net_recv_funcs) {
        const funcPtr = libc.findExportByName(funcName);
        if (funcPtr) {
            Interceptor.attach(funcPtr, {
                onLeave: function(retval: any) {
                    if (_isFridaInternal.call(this)) return;
                    try {
                        const ret = retval.toInt32();
                        if (ret <= 0) return;
                        const now = Date.now();
                        if (now - _lastRecvEvt < NET_SAMPLE_MS) return;
                        _lastRecvEvt = now;
                        bufferedSend({type: 'network', action: funcName, bytes: ret,
                            timestamp: now});
                    } catch (e) {}
                }
            });
        }
    }
}

// mmap/mprotect EXEC watchers REMOVED (T-fix): the QuickJS/V8 runtime
// allocates executable memory via mmap/mprotect too, so these hooks fired
// from inside the agent's own JS execution, serializing app threads on the
// script mutex (observed: 3-4 threads pinned at 100% CPU in sched_yield,
// ANR -> process kill).  The behavioral signal they carried (self-JIT of
// packed code) is partially covered by dlopen/memfd events instead.

if (libc) {
    const ptracePtr = libc.findExportByName('ptrace');
    if (ptracePtr) {
        Interceptor.attach(ptracePtr, {
            onEnter: function(args: any) {
                this._request = args[0].toInt32();
            },
            onLeave: function(retval: any) {
                try {
                    const PTRACE_TRACEME = 0;
                    if (this._request === PTRACE_TRACEME) {
                        retval.replace(ptr(0));
                        console.log('[BYPASS] ptrace(PTRACE_TRACEME) spoofed -> 0');
                        send({
                            type: 'bypass', action: 'ptrace_traceme',
                            original_retval: retval.toInt32(),
                            timestamp: Date.now()
                        });
                    } else {
                        bufferedSend({
                            type: 'native', action: 'ptrace',
                            request: this._request,
                            timestamp: Date.now()
                        });
                    }
                } catch (e) {}
            }
        });
        console.log('[+] ptrace anti-debug bypass installed');
    }
}

function installSSLPayloadHooks(moduleName: string) {
    const hookKey = 'ssl_payload_' + moduleName;
    if (_hookedNative[hookKey]) return;
    try {
        const mod = Process.findModuleByName(moduleName);
        if (!mod) return;

        // SSL hooks now log byte counts only — hex-encoding up to 4096 bytes
        // per SSL_read/SSL_write was extremely expensive and unnecessary for
        // LSTM behavioral modeling (the model uses event sequences, not payload content).
        const sslReadPtr = mod.findExportByName('SSL_read');
        if (sslReadPtr) {
            Interceptor.attach(sslReadPtr, {
                onLeave: function(retval: any) {
                    try {
                        const bytesRead = retval.toInt32();
                        if (bytesRead > 0) {
                            bufferedSend({
                                type: 'ssl', func: 'SSL_read', module: moduleName,
                                bytes: bytesRead,
                                timestamp: Date.now()
                            });
                        }
                    } catch (e) {}
                }
            });
            console.log('[+] SSL_read hook: ' + moduleName);
        }

        const sslWritePtr = mod.findExportByName('SSL_write');
        if (sslWritePtr) {
            Interceptor.attach(sslWritePtr, {
                onEnter: function(args: any) {
                    try {
                        const num = args[2].toInt32();
                        if (num > 0) {
                            bufferedSend({
                                type: 'ssl', func: 'SSL_write', module: moduleName,
                                bytes: num,
                                timestamp: Date.now()
                            });
                        }
                    } catch (e) {}
                }
            });
            console.log('[+] SSL_write hook: ' + moduleName);
        }

        const sslConnectPtr = mod.findExportByName('SSL_connect');
        if (sslConnectPtr) {
            Interceptor.attach(sslConnectPtr, {
                onEnter: function(args: any) {
                    bufferedSend({type: 'ssl', func: 'SSL_connect', module: moduleName, timestamp: Date.now()});
                }
            });
        }

        _hookedNative[hookKey] = true;
        console.log('[+] SSL hooks installed for: ' + moduleName);
    } catch (e) {
        console.log('[-] SSL hooks failed for ' + moduleName + ': ' + e);
    }
}

const SSL_MODULE_CANDIDATES = ['libssl.so', 'libboringssl.so', 'libconscrypt_jni.so'];
for (const sslMod of SSL_MODULE_CANDIDATES) {
    installSSLPayloadHooks(sslMod);
}

const libart = Process.findModuleByName('libart.so');
if (libart) {
    const registerNativesPatterns = ['RegisterNatives', '_ZN3art3JNI15RegisterNativesE', 'jni_RegisterNatives'];
    let RegisterNatives: any = null;
    const symbols = libart.enumerateSymbols();
    for (const pattern of registerNativesPatterns) {
        RegisterNatives = symbols.find((s: any) => s.name.includes(pattern) && s.type === 'function');
        if (RegisterNatives) break;
    }
    if (RegisterNatives) {
        Interceptor.attach(RegisterNatives.address, {
            onEnter: function(args: any) {
                const env = args[0];
                const jclass = args[1];
                const methods = args[2];
                const nMethods = args[3].toInt32();
                try {
                    console.log(`[JNI] RegisterNatives count=${nMethods}`);
                    const bt = captureBacktrace(this.context);
                    bufferedSend({type: 'native', action: 'jni_register', count: nMethods, backtrace: bt, timestamp: Date.now()});

                    const ptrSize = Process.pointerSize;
                    const structSize = ptrSize * 3;
                    for (let i = 0; i < nMethods; i++) {
                        const methodBase = methods.add(i * structSize);
                        const name = methodBase.readPointer().readUtf8String();
                        const sig = methodBase.add(ptrSize).readPointer().readUtf8String();
                        const fnPtr = methodBase.add(ptrSize * 2).readPointer();
                        
                        console.log(`  - ${name}${sig} -> ${fnPtr}`);
                        bufferedSend({
                            type: 'native', 
                            action: 'jni_method_map', 
                            method: name, 
                            sig: sig, 
                            ptr: fnPtr.toString(),
                            arch: Process.arch,
                            timestamp: Date.now()
                        });
                    }
                } catch (e) {
                    console.log(`[JNI] Error in RegisterNatives hook: ${e}`);
                }
            }
        });
        console.log('[+] RegisterNatives hook (arch=' + Process.arch + ', ptrSize=' + Process.pointerSize + ')');
    }
}


// Stalker REMOVED — Stalker JIT-rewrites native code at the instruction level.
// When it follows a Chrome/V8 or WebView GPU thread, the rewritten code
// collides with V8's own JIT compiler, causing access-violation crashes
// (the "Bad access due to invalid address" / Chrome_InProcGp SIGSEGV).
// Even on non-JIT threads, Stalker adds 50-200x overhead that triggers ANR.
// The behavioral data needed for LSTM analysis is fully captured by the
// Interceptor-based hooks above (API calls, network, crypto, file, JNI).
const _stalkerCallBuffer: any[] = [];
let _stalkerActive = false;
function flushStalkerBuffer() {}

// pthread_create watcher REMOVED (T-fix): DebugSymbol.fromAddress()
// synchronously parses /proc/self/maps + ELF headers on the JS thread;
// under multi-threaded load this serialized every hooked call behind it.

console.log('[*] Native hooks installed. Interact with the app to see activity.');
"""

    def _generate_modern_android_hooks(self) -> str:
        return """
console.log('[*] Installing modern Android hooks.');
Java.perform(() => {
    setTimeout(() => {
    try {
        const OkHttpCall = Java.use('retrofit2.OkHttpCall');
        hookAllOverloads('retrofit2.OkHttpCall', 'execute', (args: any[]) => {
            send({type: 'network', action: 'retrofit_execute', timestamp: Date.now()});
        });
        hookAllOverloads('retrofit2.OkHttpCall', 'enqueue', (args: any[]) => {
            send({type: 'network', action: 'retrofit_enqueue', timestamp: Date.now()});
        });
    } catch (e) {
        console.log('[-] Retrofit hooks: ' + e);
    }

    safeJavaHook('com.android.volley.RequestQueue', 'add', (cls: any) => {
        hookAllOverloads('com.android.volley.RequestQueue', 'add', (args: any[]) => {
            try {
                const request = args[0];
                const url = request.getUrl();
                const method = request.getMethod();
                console.log('[VOLLEY] ' + method + ' ' + url);
                send({type: 'network', action: 'volley_request', method: '' + method, url: '' + url, timestamp: Date.now()});
            } catch (e) {}
        });
    }, true);

    // malware often loads additional DEX files at runtime to hide payloads
    // T10: dump loaded dex bytes to the host for static re-analysis
    const MAX_DEX_BYTES = 8 * 1024 * 1024;
    function dumpDexFile(dexPath: string) {
        try {
            const FileCls = Java.use('java.io.File');
            const fisCls = Java.use('java.io.FileInputStream');
            const bosCls = Java.use('java.io.ByteArrayOutputStream');
            const ff = FileCls.$new(dexPath);
            if (!ff.exists()) return;
            const fis = fisCls.$new(ff);
            const chunk = Java.array('byte', new Array(65536).fill(0));
            const out = bosCls.$new();
            let n;
            while ((n = fis.read(chunk)) > 0) out.write(chunk, 0, n);
            fis.close();
            const all = out.toByteArray();
            out.close();
            if (all.length > 0 && all.length <= MAX_DEX_BYTES) {
                send({type: 'dex_dump', path: dexPath, size: all.length}, javaBytesToAb(all));
                console.log('[DEX] dumped ' + all.length + ' bytes from ' + dexPath);
            }
        } catch (e) {}
    }

    hookAllOverloads('dalvik.system.DexClassLoader', '$init', (args: any[]) => {
        const dexPath = '' + args[0];
        console.log('[DEX] DexClassLoader loading: ' + dexPath);
        let javaStack = '';
        try { javaStack = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new()); } catch(e) {}
        send({type: 'api', action: 'dex_load', path: dexPath, java_backtrace: javaStack, timestamp: Date.now()});
        setTimeout(() => { try { Java.perform(() => dumpDexFile(dexPath)); } catch (e) {} }, 250);
    });

    hookAllOverloads('dalvik.system.PathClassLoader', '$init', (args: any[]) => {
        const dexPath = '' + args[0];
        console.log('[DEX] PathClassLoader loading: ' + dexPath);
        let javaStack = '';
        try { javaStack = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new()); } catch(e) {}
        send({type: 'api', action: 'path_classloader', path: dexPath, java_backtrace: javaStack, timestamp: Date.now()});
    });

    try {
        const InMemoryDex = Java.use('dalvik.system.InMemoryDexClassLoader');
        hookAllOverloads('dalvik.system.InMemoryDexClassLoader', '$init', (args: any[]) => {
            console.log('[DEX] InMemoryDexClassLoader - dex loaded from memory!');
            let javaStack = '';
            try { javaStack = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new()); } catch(e) {}
            send({type: 'api', action: 'inmemory_dex_load', java_backtrace: javaStack, timestamp: Date.now()});
            // T10: dump the in-memory dex ByteBuffer
            setTimeout(() => {
                try {
                    Java.perform(() => {
                        const bb = args[0];
                        if (!bb) return;
                        const dup = bb.duplicate();
                        const size = dup.remaining();
                        if (size <= 0 || size > MAX_DEX_BYTES) return;
                        const jbytes = Java.array('byte', new Array(size).fill(0));
                        dup.get(jbytes);
                        send({type: 'dex_dump', path: 'in-memory', size: size}, javaBytesToAb(jbytes));
                        console.log('[DEX] dumped in-memory dex (' + size + ' bytes)');
                    });
                } catch (e) {}
            }, 250);
        });
    } catch (e) {}

    hookAllOverloads('android.content.ContentResolver', 'query', (args: any[]) => {
        try {
            const uri = '' + args[0];
            bufferedSend({type: 'api', action: 'content_query', uri: uri, timestamp: Date.now()});
        } catch (e) {}
    });

    hookAllOverloads('android.content.ContentResolver', 'insert', (args: any[]) => {
        try {
            const uri = '' + args[0];
            bufferedSend({type: 'api', action: 'content_insert', uri: uri, timestamp: Date.now()});
        } catch (e) {}
    });

    // start() takes no args — the command lives in the builder's `command`
    // field. Found live: com.ganshibiji exec events logged empty commands.
    safeJavaHook('java.lang.ProcessBuilder', 'start', (cls: any) => {
        const overloads = cls.start.overloads;
        for (let i = 0; i < overloads.length; i++) {
            const overload = overloads[i];
            overload.implementation = function() {
                let cmd: string = '';
                try {
                    const list = this.command();
                    if (list !== null && list.size() > 0) {
                        const parts: string[] = [];
                        for (let j = 0; j < list.size(); j++) parts.push('' + list.get(j));
                        cmd = parts.join(' ');
                    }
                } catch (e) {}
                console.log('[EXEC] ProcessBuilder.start(): ' + cmd);
                bufferedSend({type: 'exec', action: 'process_builder', command: cmd, timestamp: Date.now()});
                return overload.apply(this, arguments);
            };
        }
    });

    const _systemPrefixes = [
        'java.', 'javax.', 'sun.', 'com.sun.', 'dalvik.', 'libcore.',
        'android.', 'androidx.', 'com.android.', 'com.google.android.',
        'kotlin.', 'kotlinx.', 'org.json.', 'org.xml.', 'org.w3c.',
        'org.apache.harmony.', 'org.apache.http.',
    ];

    function _isSystemClass(className: string): boolean {
        for (let i = 0; i < _systemPrefixes.length; i++) {
            if (className.indexOf(_systemPrefixes[i]) === 0) return true;
        }
        return false;
    }

    let _invokeGuard: any = {};  // thread-local guard: tid -> true

    safeJavaHook('java.lang.reflect.Method', 'invoke', (cls: any) => {
        const origInvoke = cls.invoke;
        const invokeOverloads = origInvoke.overloads;
        for (let i = 0; i < invokeOverloads.length; i++) {
            (function(overload: any) {
                overload.implementation = function() {
                    const tid = Process.getCurrentThreadId();
                    if (!_invokeGuard[tid]) {
                        _invokeGuard[tid] = true;
                        try {
                            const declaringClass = '' + this.getDeclaringClass().getName();
                            if (!_isSystemClass(declaringClass)) {
                                const mName = '' + this.getName();
                                bufferedSend({type: 'api', action: 'reflect_invoke', className: declaringClass, method: mName, timestamp: Date.now()});
                            }
                        } catch (e) {}
                        _invokeGuard[tid] = false;
                    }
                    return overload.apply(this, arguments);
                };
            })(invokeOverloads[i]);
        }
    });

    hookAllOverloads('java.lang.Class', 'forName', (args: any[]) => {
        try {
            const className = '' + args[0];
            if (!_isSystemClass(className)) {
                bufferedSend({type: 'api', action: 'class_forname', className: className, timestamp: Date.now()});
            }
        } catch (e) {}
    });

    safeJavaHook('android.hardware.Camera', 'open', (cls: any) => {
        hookAllOverloads('android.hardware.Camera', 'open', (args: any[]) => {
            console.log('[API] Camera.open()');
            send({type: 'api', action: 'camera_open', timestamp: Date.now()});
        });
    });

    safeJavaHook('android.media.AudioRecord', '$init', (cls: any) => {
        hookAllOverloads('android.media.AudioRecord', '$init', (args: any[]) => {
            console.log('[API] AudioRecord created (microphone access)');
            send({type: 'api', action: 'audio_record', timestamp: Date.now()});
        });
    });

    safeJavaHook('android.content.ClipboardManager', 'getPrimaryClip', (cls: any) => {
        hookAllOverloads('android.content.ClipboardManager', 'getPrimaryClip', (args: any[]) => {
            console.log('[API] ClipboardManager.getPrimaryClip()');
            send({type: 'api', action: 'clipboard_read', timestamp: Date.now()});
        });
    });

    safeJavaHook('android.accounts.AccountManager', 'getAccounts', (cls: any) => {
        hookAllOverloads('android.accounts.AccountManager', 'getAccounts', (args: any[]) => {
            console.log('[API] AccountManager.getAccounts()');
            send({type: 'api', action: 'get_accounts', timestamp: Date.now()});
        });
    });

    console.log('[+] Modern Android hooks installed');
    }, 3500);
});
"""

    def _generate_dlopen_watcher(self) -> str:
        return """
console.log('[*] Installing dlopen watcher.');
function installSSLHooksForModule(moduleName: string) {
    // ensures late-loaded SSL libraries also get full payload capture--not just event-level logging.
    installSSLPayloadHooks(moduleName);
}

function scanStaticJniExports(libPath: string) {
    try {
        const libName = libPath.split('/').pop() as string;
        if (_hookedNative['jni_scan_' + libName]) return;
        _hookedNative['jni_scan_' + libName] = true;
        const mod = Process.findModuleByName(libName);
        if (!mod) return;
        const exports = mod.enumerateExports();
        for (const exp of exports) {
            if (exp.name && exp.name.startsWith('Java_')) {
                console.log('[JNI-STATIC] ' + libName + ' exports: ' + exp.name);
                bufferedSend({type: 'native', action: 'jni_static_export',
                    library: libName, func: exp.name, ptr: exp.address.toString(),
                    timestamp: Date.now()});
            }
        }
    } catch (e) {}
}

try {
    const _dlopenCallbacks = {
        onEnter: function(this: any, args: any) {
            try {
                const path = args[0] ? args[0].readUtf8String() : null;
                if (path) {
                    this._dlopenPath = path;
                    this._dlopenBt = captureBacktrace(this.context);
                }
            } catch (e) {}
        },
        onLeave: function(this: any, retval: any) {
            if (!this._dlopenPath) return;
            const path = this._dlopenPath;
            const libName = path.split('/').pop();

            bufferedSend({type: 'native', action: 'dlopen', path: path, library: libName, backtrace: this._dlopenBt || [], timestamp: Date.now()});
            setTimeout(() => { scanStaticJniExports(path); }, 50);

            if (libName && (libName.indexOf('ssl') !== -1 || libName.indexOf('crypto') !== -1 ||
                libName.indexOf('boring') !== -1 || libName.indexOf('conscrypt') !== -1)) {
                console.log('[DLOPEN] SSL-related library loaded: ' + path);
                setTimeout(() => { installSSLHooksForModule(libName as string); }, 100);
            }

            const suspicious = ['payload', 'shell', 'exploit', 'inject', 'hack', 'root', 'hide'];
            for (const kw of suspicious) {
                if (libName && libName.toLowerCase().indexOf(kw) !== -1) {
                    console.log('[!] SUSPICIOUS library loaded: ' + path);
                    bufferedSend({type: 'native', action: 'suspicious_lib', path: path, keyword: kw, timestamp: Date.now()});
                }
            }
        }
    };

    function _findExport(funcName: string, candidates: string[]): any {
        for (const modName of candidates) {
            try {
                const mod = Process.findModuleByName(modName);
                if (mod) {
                    const addr = mod.findExportByName(funcName);
                    if (addr) return addr;
                }
            } catch (e) {}
        }
        return null;
    }

    const _dlopenCandidates = ['libc.so', 'libdl.so', 'linker64', 'linker'];
    const dlopenPtr = _findExport('dlopen', _dlopenCandidates);
    const androidDlopenExtPtr = _findExport('android_dlopen_ext', _dlopenCandidates);

    let _dlopenWatcherOk = false;
    if (dlopenPtr) {
        Interceptor.attach(dlopenPtr, _dlopenCallbacks);
        console.log('[+] dlopen watcher');
        _dlopenWatcherOk = true;
    }
    if (androidDlopenExtPtr) {
        Interceptor.attach(androidDlopenExtPtr, _dlopenCallbacks);
        console.log('[+] android_dlopen_ext watcher');
        _dlopenWatcherOk = true;
    }
    if (!_dlopenWatcherOk) {
        console.log('[~] dlopen watcher: no dlopen/android_dlopen_ext export found (hooks via libc & SSL still active)');
    }
} catch (e) {
    console.log('[-] dlopen watcher failed: ' + e);
}
"""

    def _generate_deferred_hooks(self) -> str:
        return """
console.log('[*] Installing deferred hook system.');

const DEFERRED_TARGETS: any = {
    'okhttp3.OkHttpClient': {
        methods: ['newCall'],
        hooked: false,
        callback: function(args: any[], method: string) {
            try {
                const url = args[0].url().toString();
                const m = args[0].method();
                send({type: 'network', action: 'okhttp_request', method: m, url: url, timestamp: Date.now()});
            } catch (e) {}
        }
    },
    'com.squareup.okhttp.OkHttpClient': {
        methods: ['newCall'],
        hooked: false,
        callback: function(args: any[], method: string) {
            try {
                const url = args[0].urlString();
                send({type: 'network', action: 'okhttp2_request', url: url, timestamp: Date.now()});
            } catch (e) {}
        }
    },
    'com.android.okhttp.internal.huc.HttpURLConnectionImpl': {
        methods: ['getInputStream', 'getOutputStream'],
        hooked: false,
        callback: function(args: any[], method: string) {
            send({type: 'network', action: 'internal_http', method: method, timestamp: Date.now()});
        }
    }
};

function tryDeferredHooks() {
    try {
        Java.perform(() => {
            if (typeof Java.enumerateClassLoaders !== 'function') {
                for (const className in DEFERRED_TARGETS) {
                    const target = DEFERRED_TARGETS[className];
                    if (target.hooked || _hookedClasses[className]) continue;
                    try {
                        Java.use(className);
                        for (const methodName of target.methods) {
                            if (_hookedClasses[className + '.' + methodName]) continue;
                            hookAllOverloads(className, methodName, target.callback);
                        }
                        target.hooked = true;
                        console.log('[DEFERRED] Late-hooked ' + className);
                        send({type: 'hook', action: 'deferred_success', className: className, timestamp: Date.now()});
                    } catch (e) {}
                }
                return;
            }

            Java.enumerateClassLoaders({
                onMatch: function(loader: any) {
                    try {
                        let factory: any;
                        if (typeof (Java as any).ClassFactory !== 'undefined' &&
                            typeof (Java as any).ClassFactory.get === 'function') {
                            factory = (Java as any).ClassFactory.get(loader);
                        } else {
                            (Java.classFactory as any).loader = loader;
                            factory = Java.classFactory;
                        }

                        for (const className in DEFERRED_TARGETS) {
                            const target = DEFERRED_TARGETS[className];
                            if (target.hooked) continue;
                            try {
                                const cls = factory.use(className);
                                for (const methodName of target.methods) {
                                    hookAllOverloads(className, methodName, target.callback);
                                }
                                target.hooked = true;
                                console.log('[DEFERRED] Late-hooked ' + className + ' via classloader');
                                send({type: 'hook', action: 'deferred_success', className: className, timestamp: Date.now()});
                            } catch (e) {
                                // next
                            }
                        }
                    } catch (e) {}
                },
                onComplete: function() {}
            });

            try {
                if (typeof (Java as any).ClassFactory === 'undefined' ||
                    typeof (Java as any).ClassFactory.get !== 'function') {
                    (Java.classFactory as any).loader = null;
                }
            } catch(e) {}
        });
    } catch (e) {
        console.log('[-] Deferred hooks failed: ' + e);
    }
}

setTimeout(tryDeferredHooks, 3000);
setTimeout(tryDeferredHooks, 8000);
setTimeout(tryDeferredHooks, 15000);

// Block removed due to extreme performance overhead and ANR generation
// console.log('[*] All hooks installed. Interact with the app to capture behavior.');

// lets the py-host flush buffered events before detaching
rpc.exports = {
    flushBuffers: function() {
        try { flushIpcBuffer(); } catch (e) {}
        try { flushStalkerBuffer(); } catch (e) {}
        return { ipc: _ipcBuffer.length, stalker: _stalkerCallBuffer.length };
    },
    // T15: per-type event counts + installed-hook counts
    getStats: function() {
        try { flushIpcBuffer(); } catch (e) {}
        return { events: _evtStats, hooks: _hookStats };
    },
    dispose: function() {
        try { flushIpcBuffer(); } catch (e) {}
        try { flushStalkerBuffer(); } catch (e) {}
        if (_stalkerActive) {
            try { Stalker.flush(); } catch (e) {}
            try { Stalker.unfollow(); } catch (e) {}
        }
    }
};
"""


def extract_package_name(decompiled_dir: Path) -> Optional[str]:
    manifest_path = decompiled_dir / "AndroidManifest.xml"
    if not manifest_path.exists():
        return None
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        return root.get("package")
    except Exception:
        return None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        script_dir = Path(__file__).parent.parent
        decompiled_dir = script_dir / "data" / "base_decompiled"
        if not decompiled_dir.exists():
            print("Usage: python framework_detector.py <decompiled_apk_dir>")
            print("   or: python framework_detector.py  (uses data/base_decompiled)")
            sys.exit(1)
    else:
        decompiled_dir = Path(sys.argv[1])

    package_name = extract_package_name(decompiled_dir)
    if package_name:
        print(f"[*] package: {package_name}")
    detector = FrameworkDetector(decompiled_dir)
    frameworks = detector.detect_all()
    if not frameworks:
        print("[!] no frameworks detected")
        sys.exit(1)

    for fw in frameworks:
        bar = "█" * int(fw.confidence * 20)
        print(f"  {fw.name:20} {bar} {fw.confidence:.1%}")

    generator = HookGenerator(frameworks)
    script, is_typescript = generator.generate_hooks()
    if is_typescript:
        output_file = Path(__file__).parent / "hooks" / "generated_hooks.ts"
    else:
        output_file = Path(__file__).parent / "hooks" / "generated_hooks.js"
    output_file.write_text(script)

    if package_name:
        if is_typescript:
            print(
                f"\n[*] compile: frida-compile {output_file.name} -o generated_hooks.js"
            )
            print(
                f"[*] run: frida -U -f {package_name} -l src/hooks/generated_hooks.js"
            )
        else:
            print(f"\n[*] run: frida -U -f {package_name} -l {output_file}")

    print()
