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
        """Scan smali files for framework indicator strings.
        
        Also checks classes.dex directly if present (faster for large APKs).
        No arbitrary file cap — scans all smali files for completeness.
        """
        # fast path: check raw classes.dex string table first (binary grep)
        for dex_file in self.decompiled_dir.parent.glob("*.dex"):
            try:
                dex_bytes = dex_file.read_bytes()
                dex_text = dex_bytes.decode("utf-8", errors="ignore")
                if any(s in dex_text for s in strings):
                    return True
            except Exception:
                continue

        # fallback: scan all smali files
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
        """Check for native C/C++ libraries (lib/*/*.so), not smali bytecode."""
        lib_dir = self.decompiled_dir / "lib"
        if lib_dir.exists():
            if list(lib_dir.rglob("*.so")):
                return True
        return False

    def _detect_kotlin(self) -> bool:
        """Detect whether the app uses Kotlin (vs plain Java).

        Kotlin apps include kotlin.Metadata annotations, kotlin/ stdlib
        classes, or META-INF/**.kotlin_module files.
        """
        for smali_dir in self.decompiled_dir.glob("smali*"):
            kotlin_dir = smali_dir / "kotlin"
            if kotlin_dir.exists():
                return true

            metadata_file = smali_dir / "kotlin" / "Metadata.smali"
            if metadata_file.exists():
                return True

        meta_inf = self.decompiled_dir / "original" / "META-INF"
        if meta_inf.exists():
            if list(meta_inf.rglob("*.kotlin_module")):
                return True

        return False


class HookGenerator:
    def __init__(self, frameworks: List[FrameworkSignature]):
        self.frameworks = frameworks

    def generate_hooks(self) -> tuple[str, bool]:
        """Generate hooks and return (script_content, is_typescript)"""
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
declare const ptr: any;
declare const NULL: any;

console.log('[*] Detected frameworks: """
            + fw_names
            + """');
"""
        )
        is_typescript = True

        # global exception handler + utility helpers
        script += self._generate_preamble()

        # anti-detection bypass (root/frida detection, SSL pinning)
        script += self._generate_anti_detection_bypass()

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

        # kotlin or retrofit or modern android hooks
        script += self._generate_modern_android_hooks()

        # (dlopen) for late-loaded .so
        script += self._generate_dlopen_watcher()

        # deferred class hooking via classloader enumeration
        script += self._generate_deferred_hooks()
        script = re.sub(r'(?<![a-zA-Z_])send\(', '_send(', script)

        return script, is_typescript

    def _generate_preamble(self) -> str:
        return """
// prevents hook errors from crashing the app
Process.setExceptionHandler(function(details: any) {
    console.log('[!] Exception in ' + details.type + ' at ' + details.address +
                ' context: ' + JSON.stringify(details.context));
    return true; // suppress the exception, keep the process alive
});

// send() is read-only in Frida 17+ ESM runtime — cannot be reassigned on
// globalThis.  Instead, define a wrapper that injects thread_id and call it
// throughout the hooks.
const _fridaSend = send;
function _send(payload: any, data?: any) {
    if (typeof payload === 'object' && payload !== null) {
        payload.thread_id = Process.getCurrentThreadId();
    }
    _fridaSend(payload, data !== undefined ? data : null);
}

// catches errors per-hook so one failing hook does not prevent others from installing
function safeJavaHook(className: string, methodName: string, hookFn: (cls: any) => void) {
    try {
        const cls = Java.use(className);
        hookFn(cls);
        console.log('[+] Hooked ' + className + '.' + methodName);
    } catch (e) {
        console.log('[-] Failed to hook ' + className + '.' + methodName + ': ' + e);
    }
}

function hookAllOverloads(className: string, methodName: string, callback: (args: any[], method: string, overloadSig: string) => void) {
    try {
        const cls = Java.use(className);
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
                try {
                    callback(args, methodName, sig);
                } catch (cbErr) {
                    // do not let callback errors break the original method
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
        Interceptor.attach(funcPtr, callbacks);
        console.log('[+] Native hook: ' + moduleName + '!' + funcName);
        return true;
    } catch (e) {
        console.log('[-] Native hook failed: ' + moduleName + '!' + funcName + ': ' + e);
        return false;
    }
}

function captureBacktrace(ctx: any): string[] {
    try {
        const bt = Thread.backtrace(ctx, Backtracer.ACCURATE);
        return bt.map(DebugSymbol.fromAddress).map((s: any) => s.toString());
    } catch (e) {
        return [];
    }
}

const _hookedNative: any = {};  // track which native funcs we already hooked
const _hookedClasses: any = {}; // track which Java classes we already hooked
"""

    def _generate_anti_detection_bypass(self) -> str:
        return """
// ============================================================
// Anti-Detection Bypass: Root, Frida, and SSL pinning
// malware often detects analysis environments and changes behavior
// ============================================================
console.log('[*] Installing anti-detection bypass.');

Java.perform(() => {
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
            send({type: 'bypass', action: 'exec_block', command: cmdStr, timestamp: Date.now()});
        }
        send({type: 'exec', action: 'runtime_exec', command: cmdStr, backtrace: [], timestamp: Date.now()});
    });

    // apps detect frida by scanning /proc/self/maps for frida-agent, checking
    // default frida port 27042, or scanning for frida-server in process list.

    // block reading /proc/self/maps; detect injected libraries
    safeJavaHook('java.io.BufferedReader', 'readLine', (cls: any) => {
        const origReadLine = cls.readLine.overloads[0];
        origReadLine.implementation = function() {
            let line = origReadLine.call(this);
            while (line !== null) {
                const lineStr = line.toString();
                if (lineStr.indexOf('frida') !== -1 || lineStr.indexOf('gadget') !== -1 ||
                    lineStr.indexOf('gmain') !== -1 || lineStr.indexOf('linjector') !== -1) {
                    console.log('[BYPASS] /proc/maps frida detection line hidden');
                    send({type: 'bypass', action: 'frida_maps_hide', timestamp: Date.now()});
                    line = origReadLine.call(this);  // read next, non-recursively
                    continue;
                }
                break;
            }
            return line;
        };
    });

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
            NetworkSecurityConfig.isCleartextTrafficPermitted.overloads.forEach((overload: any) => {
                overload.implementation = function() {
                    return true;
                };
            });
            console.log('[+] NetworkSecurityConfig cleartext bypass');
        }
    } catch (e) {}

    console.log('[+] Anti-detection bypass installed');
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
    hookAllOverloads('javax.crypto.Cipher', 'doFinal', (args: any[], method: string, sig: string) => {
        try {
            send({type: 'crypto', action: 'cipher_dofinal', overload: sig, timestamp: Date.now()});
        } catch (e) {}
    });

    hookAllOverloads('javax.crypto.Cipher', 'getInstance', (args: any[], method: string, sig: string) => {
        try {
            const transformation = '' + args[0];
            console.log('[Crypto] Cipher.getInstance(' + transformation + ')');
            send({type: 'crypto', action: 'cipher_getinstance', transformation: transformation, timestamp: Date.now()});
        } catch (e) {}
    });

    hookAllOverloads('java.security.MessageDigest', 'digest', (args: any[], method: string, sig: string) => {
        try {
            send({type: 'crypto', action: 'digest', overload: sig, timestamp: Date.now()});
        } catch (e) {}
    });

    hookAllOverloads('java.security.MessageDigest', 'getInstance', (args: any[], method: string, sig: string) => {
        try {
            const algo = '' + args[0];
            console.log('[Crypto] MessageDigest.getInstance(' + algo + ')');
            send({type: 'crypto', action: 'digest_getinstance', algorithm: algo, timestamp: Date.now()});
        } catch (e) {}
    });

    // captures encryption keys being created
    hookAllOverloads('javax.crypto.spec.SecretKeySpec', '$init', (args: any[], method: string, sig: string) => {
        try {
            const algo = '' + args[1];
            console.log('[Crypto] SecretKeySpec created for: ' + algo);
            send({type: 'crypto', action: 'secret_key', algorithm: algo, timestamp: Date.now()});
        } catch (e) {}
    });

    hookAllOverloads('javax.crypto.KeyGenerator', 'getInstance', (args: any[], method: string, sig: string) => {
        try {
            const algo = '' + args[0];
            console.log('[Crypto] KeyGenerator.getInstance(' + algo + ')');
            send({type: 'crypto', action: 'keygen', algorithm: algo, timestamp: Date.now()});
        } catch (e) {}
    });

    console.log('[+] Crypto hooks');
});
"""

    def _generate_android_api_hooks(self) -> str:
        return """
console.log('[*] Installing Android API hooks.');
Java.perform(() => {
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
});
"""

    def _generate_java_network_hooks(self) -> str:
        return """
console.log('[*] Installing Java network hooks.');
Java.perform(() => {
    hookAllOverloads('java.net.HttpURLConnection', 'getInputStream', (args: any[]) => {
        send({type: 'network', action: 'http_request', timestamp: Date.now()});
    });

    safeJavaHook('com.android.okhttp.internal.huc.HttpURLConnectionImpl', 'getInputStream', (cls: any) => {
        cls.getInputStream.implementation = function() {
            try {
                const url = this.getURL().toString();
                const method = this.getRequestMethod();
                console.log('[HTTP] ' + method + ' ' + url);
                send({type: 'network', action: 'http_request', method: method, url: url, timestamp: Date.now()});
            } catch (e) {}
            return this.getInputStream();
        };
    });

    safeJavaHook('com.android.okhttp.internal.huc.HttpURLConnectionImpl', 'getOutputStream', (cls: any) => {
        cls.getOutputStream.implementation = function() {
            try {
                const url = this.getURL().toString();
                const method = this.getRequestMethod();
                console.log('[HTTP] ' + method + ' ' + url + ' (body)');
                send({type: 'network', action: 'http_request_body', method: method, url: url, timestamp: Date.now()});
            } catch (e) {}
            return this.getOutputStream();
        };
    });

    // HttpsURLConnection
    safeJavaHook('javax.net.ssl.HttpsURLConnection', 'getInputStream', (cls: any) => {
        cls.getInputStream.implementation = function() {
            try {
                const url = this.getURL().toString();
                const method = this.getRequestMethod();
                console.log('[HTTPS] ' + method + ' ' + url);
                send({type: 'network', action: 'https_request', method: method, url: url, timestamp: Date.now()});
            } catch (e) {}
            return this.getInputStream();
        };
    });

    // OkHttp3
    safeJavaHook('okhttp3.OkHttpClient', 'newCall', (cls: any) => {
        cls.newCall.implementation = function(request: any) {
            try {
                const url = request.url().toString();
                const method = request.method();
                console.log('[OKHTTP] ' + method + ' ' + url);
                send({type: 'network', action: 'okhttp_request', method: method, url: url, timestamp: Date.now()});
            } catch (e) {}
            return this.newCall(request);
        };
    });

    // OkHttp3 response body
    safeJavaHook('okhttp3.ResponseBody', 'string', (cls: any) => {
        cls.string.implementation = function() {
            const body = this.string();
            try {
                const preview = body.length > 500 ? body.substring(0, 500) + '...' : body;
                send({type: 'network', action: 'okhttp_response', body: preview, size: body.length, timestamp: Date.now()});
            } catch (e) {}
            return body;
        };
    });

    hookAllOverloads('java.net.Socket', '$init', (args: any[]) => {
        try {
            if (args.length >= 2) {
                const host = '' + args[0];
                const port = args[1];
                console.log('[SOCKET] ' + host + ':' + port);
                send({type: 'network', action: 'socket_connect', host: host, port: '' + port, timestamp: Date.now()});
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
                send({type: 'network', action: 'url_init', url: url, timestamp: Date.now()});

                for (const endpoint of DOH_ENDPOINTS) {
                    if (url.indexOf(endpoint) !== -1 &&
                        (url.indexOf('/dns-query') !== -1 || url.indexOf('/resolve') !== -1)) {
                        console.log('[!!! DoH] DNS-over-HTTPS detected: ' + url);
                        send({type: 'network', action: 'doh_request', url: url,
                              endpoint: endpoint, timestamp: Date.now()});
                        break;
                    }
                }
            }
        } catch (e) {}
    });

    console.log('[+] Java network hooks');
});
"""

    def _generate_native_hooks(self) -> str:
        return """
console.log('[*] Installing native hooks.');

// prevents frida message-queue overload on high-freq hooks
const _ipcBuffer: any[] = [];
const IPC_FLUSH_MS = 300;
const IPC_MAX_SIZE = 80;

function bufferedSend(evt: any) {
    evt.thread_id = Process.getCurrentThreadId();
    _ipcBuffer.push(evt);
    if (_ipcBuffer.length >= IPC_MAX_SIZE) flushIpcBuffer();
}

function flushIpcBuffer() {
    if (_ipcBuffer.length === 0) return;
    send({type: 'batch', events: _ipcBuffer.splice(0)});
}

setInterval(flushIpcBuffer, IPC_FLUSH_MS);

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

    // dns hooks 
    const getaddrinfoPtr = libc.findExportByName('getaddrinfo');
    if (getaddrinfoPtr) {
        Interceptor.attach(getaddrinfoPtr, {
            onEnter: function(args: any) {
                try {
                    const host = args[0].readUtf8String();
                    if (host) {
                        console.log('[DNS] getaddrinfo: ' + host);
                        bufferedSend({type: 'network', action: 'dns_resolve', host: host, timestamp: Date.now()});
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
                        bufferedSend({type: 'network', action: 'connect', ip: ip, port: port, backtrace: bt, timestamp: Date.now()});
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
                        bufferedSend({type: 'network', action: 'connect', ip: ip, port: port, backtrace: bt, timestamp: Date.now()});
                    }
                } catch (e) {}
            }
        });
    }

    // capture first 128 bytes of payload for C2 fingerprinting
    const net_send_funcs = ['send', 'sendto'];
    for (const funcName of net_send_funcs) {
        const funcPtr = libc.findExportByName(funcName);
        if (funcPtr) {
            Interceptor.attach(funcPtr, {
                onEnter: function(args: any) {
                    try {
                        const len = args[2].toInt32();
                        const preview = len > 0 ? args[1].readByteArray(Math.min(len, 128)) : null;
                        bufferedSend({type: 'network', action: funcName, bytes: len,
                            payload_hex: preview ? Array.from(new Uint8Array(preview as ArrayBuffer))
                                .map((b: number) => b.toString(16).padStart(2,'0')).join('') : null,
                            timestamp: Date.now()});
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
                onEnter: function(args: any) {
                    this._buf = args[1];
                    this._maxLen = args[2].toInt32();
                },
                onLeave: function(retval: any) {
                    try {
                        const ret = retval.toInt32();
                        if (ret > 0 && this._buf) {
                            const preview = this._buf.readByteArray(Math.min(ret, 128));
                            bufferedSend({type: 'network', action: funcName, bytes: ret,
                                payload_hex: Array.from(new Uint8Array(preview as ArrayBuffer))
                                    .map((b: number) => b.toString(16).padStart(2,'0')).join(''),
                                timestamp: Date.now()});
                        }
                    } catch (e) {}
                }
            });
        }
    }
}

// PROT_EXEC = 0x4, PROT_WRITE = 0x2, PROT_READ = 0x1
if (libc) {
    const PROT_EXEC = 0x4;
    const _mmapTracker: any = {};  // address -> {length, prot, flags, fd, timestamp, bt}

    const mmapPtr = libc.findExportByName('mmap');
    if (mmapPtr) {
        Interceptor.attach(mmapPtr, {
            onEnter: function(args: any) {
                this._addr = args[0];
                this._len = args[1].toInt32();
                this._prot = args[2].toInt32();
                this._flags = args[3].toInt32();
                this._fd = args[4].toInt32();
            },
            onLeave: function(retval: any) {
                try {
                    const prot = this._prot;
                    const MAP_ANONYMOUS = 0x20;
                    const isExec = (prot & PROT_EXEC) !== 0;
                    const isAnon = (this._flags & MAP_ANONYMOUS) !== 0;
                    
                    if (isExec) {
                        const protStr = ((prot & 1) ? 'R' : '-') + ((prot & 2) ? 'W' : '-') + ((prot & 4) ? 'X' : '-');
                        const bt = captureBacktrace(this.context);
                        bufferedSend({
                            type: 'native', action: 'mmap_exec',
                            address: retval.toString(),
                            length: this._len,
                            prot: protStr,
                            prot_raw: prot,
                            flags: this._flags,
                            fd: this._fd,
                            is_anonymous: isAnon,
                            backtrace: bt,
                            timestamp: Date.now()
                        });
                        console.log('[!] mmap with EXEC prot=' + protStr + ' len=' + this._len + ' addr=' + retval);
                    }
                    
                    if (isAnon && this._len > 4096 && !isExec) {
                        const addrKey = retval.toString();
                        _mmapTracker[addrKey] = {
                            length: this._len,
                            prot: prot,
                            flags: this._flags,
                            timestamp: Date.now()
                        };

                        const keys = Object.keys(_mmapTracker);
                        if (keys.length > 500) {
                            delete _mmapTracker[keys[0]];
                        }
                    }
                } catch (e) {}
            }
        });
        console.log('[+] mmap hook installed');
    }

    const mprotectPtr = libc.findExportByName('mprotect');
    if (mprotectPtr) {
        Interceptor.attach(mprotectPtr, {
            onEnter: function(args: any) {
                try {
                    const addr = args[0];
                    const len = args[1].toInt32();
                    const prot = args[2].toInt32();

                    if ((prot & PROT_EXEC) !== 0) {
                        const protStr = ((prot & 1) ? 'R' : '-') + ((prot & 2) ? 'W' : '-') + ((prot & 4) ? 'X' : '-');
                        const bt = captureBacktrace(this.context);
                        const addrStr = addr.toString();
                        
                        const mmapInfo = _mmapTracker[addrStr];
                        const wasAnonymous = !!mmapInfo;
                        
                        console.log('[!!! MPROTECT] Making memory executable: addr=' + addr + ' len=' + len + ' prot=' + protStr +
                            (wasAnonymous ? ' [SUSPICIOUS: prev anon mmap]' : ''));
                        send({
                            type: 'native', action: 'mprotect_exec',
                            address: addrStr,
                            length: len,
                            prot: protStr,
                            prot_raw: prot,
                            was_anonymous_mmap: wasAnonymous,
                            original_mmap_size: mmapInfo ? mmapInfo.length : null,
                            backtrace: bt,
                            timestamp: Date.now()
                        });
                        
                        if (wasAnonymous) {
                            delete _mmapTracker[addrStr];
                        }
                    }
                } catch (e) {}
            }
        });
        console.log('[+] mprotect hook installed');
    }
}

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
                        // return 0 (success) to make malware think it self-traced
                        retval.replace(ptr(0));
                        console.log('[BYPASS] ptrace(PTRACE_TRACEME) spoofed -> 0');
                        send({
                            type: 'bypass', action: 'ptrace_traceme',
                            original_retval: retval.toInt32(),
                            timestamp: Date.now()
                        });
                    } else {
                        send({
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

        const sslReadPtr = mod.findExportByName('SSL_read');
        if (sslReadPtr) {
            Interceptor.attach(sslReadPtr, {
                onEnter: function(args: any) {
                    this._ssl = args[0];
                    this._buf = args[1];
                    this._num = args[2].toInt32();
                },
                onLeave: function(retval: any) {
                    try {
                        const bytesRead = retval.toInt32();
                        if (bytesRead > 0 && this._buf) {
                            const preview = this._buf.readByteArray(Math.min(bytesRead, 4096));
                            bufferedSend({
                                type: 'ssl', func: 'SSL_read', module: moduleName,
                                bytes: bytesRead,
                                payload_hex: preview ? Array.from(new Uint8Array(preview as ArrayBuffer))
                                    .map((b: number) => b.toString(16).padStart(2, '0')).join('') : null,
                                timestamp: Date.now()
                            });
                        }
                    } catch (e) {}
                }
            });
            console.log('[+] SSL_read payload hook: ' + moduleName);
        }

        const sslWritePtr = mod.findExportByName('SSL_write');
        if (sslWritePtr) {
            Interceptor.attach(sslWritePtr, {
                onEnter: function(args: any) {
                    try {
                        const num = args[2].toInt32();
                        if (num > 0) {
                            const preview = args[1].readByteArray(Math.min(num, 4096));
                            bufferedSend({
                                type: 'ssl', func: 'SSL_write', module: moduleName,
                                bytes: num,
                                payload_hex: preview ? Array.from(new Uint8Array(preview as ArrayBuffer))
                                    .map((b: number) => b.toString(16).padStart(2, '0')).join('') : null,
                                timestamp: Date.now()
                            });
                        }
                    } catch (e) {}
                }
            });
            console.log('[+] SSL_write payload hook: ' + moduleName);
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
        console.log('[+] SSL payload hooks installed for: ' + moduleName);
    } catch (e) {
        console.log('[-] SSL payload hooks failed for ' + moduleName + ': ' + e);
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
                        send({
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


const _stalkerCallBuffer: any[] = [];
const STALKER_FLUSH_INTERVAL = 2000;   // flush every 2s
const STALKER_MAX_BUFFER = 500;
let _stalkerActive = false;

function flushStalkerBuffer() {
    if (_stalkerCallBuffer.length === 0) return;
    const events = _stalkerCallBuffer.splice(0, STALKER_MAX_BUFFER);
    send({
        type: 'stalker',
        action: 'call_graph',
        count: events.length,
        events: events,
        timestamp: Date.now()
    });
}

function startStalker(threadId: number) {
    if (_stalkerActive) return;
    try {
        Stalker.follow(threadId, {
            events: {
                call: true,    // capture CALL instructions
                ret: false,    // skip returns
                exec: false,   // skip basic blocks
                block: false,  // skip block compilation
                compile: false
            },
            onCallSummary: function(summary: any) {
                try {
                    for (const target in summary) {
                        const addr = ptr(target);
                        const sym = DebugSymbol.fromAddress(addr);
                        const moduleName = sym.moduleName || '';
                        const funcName = sym.name || '';

                        // filter out noise: only log calls to known libraries and non-trivial call counts
                        if (summary[target] > 0 && moduleName) {
                            _stalkerCallBuffer.push({
                                address: target,
                                module: moduleName,
                                func: funcName,
                                count: summary[target]
                            });
                        }
                    }
                    if (_stalkerCallBuffer.length >= STALKER_MAX_BUFFER) {
                        flushStalkerBuffer();
                    }
                } catch (e) {}
            }
        });
        _stalkerActive = true;
        console.log('[+] Stalker following thread ' + threadId + ' (arch=' + Process.arch + ')');
        setInterval(flushStalkerBuffer, STALKER_FLUSH_INTERVAL);
    } catch (e) {
        console.log('[-] Stalker failed: ' + e);
        console.log('    Stalker requires arm64 or x86_64. Current arch: ' + Process.arch);
    }
}

setTimeout(() => {
    try {
        Java.perform(() => {
            try {
                const Looper = Java.use('android.os.Looper');
                const mainLooper = Looper.getMainLooper();
                const mainThread = mainLooper.getThread();
                const appMainTid = mainThread.getId();
                console.log('[*] App main thread ID: ' + appMainTid);
                const threads = Process.enumerateThreads();
                let targetTid = threads[0].id;
                for (const t of threads) {
                    if (t.id === appMainTid) {
                        targetTid = t.id;
                        break;
                    }
                }
                startStalker(threads[0].id);
            } catch (e) {
                console.log('[-] Could not determine app main thread: ' + e);
                const threads = Process.enumerateThreads();
                if (threads.length > 0) {
                    startStalker(threads[0].id);
                }
            }
        });
    } catch (e) {
        console.log('[-] Could not start Stalker: ' + e);
    }
}, 3000);

if (libc) {
    const pthreadCreatePtr = libc.findExportByName('pthread_create');
    if (pthreadCreatePtr) {
        Interceptor.attach(pthreadCreatePtr, {
            onEnter: function(args: any) {
                try {
                    const startRoutine = args[2];
                    const sym = DebugSymbol.fromAddress(startRoutine);
                    const moduleName = sym.moduleName || '';
                    if (moduleName && moduleName.indexOf('lib') === 0 &&
                        moduleName.indexOf('libc.so') === -1 &&
                        moduleName.indexOf('libart.so') === -1 &&
                        moduleName.indexOf('libandroid_runtime.so') === -1) {
                        bufferedSend({
                            type: 'native', action: 'pthread_create',
                            start_routine: startRoutine.toString(),
                            module: moduleName,
                            func: sym.name || '',
                            timestamp: Date.now()
                        });
                    }
                } catch (e) {}
            }
        });
        console.log('[+] pthread_create watcher');
    }
}

console.log('[*] Native hooks installed. Interact with the app to see activity.');
"""

    def _generate_modern_android_hooks(self) -> str:
        return """
console.log('[*] Installing modern Android hooks.');
Java.perform(() => {
    try {
        const classes = Java.enumerateLoadedClassesSync();
        for (let i = 0; i < classes.length; i++) {
            if (classes[i] === 'retrofit2.OkHttpCall' || classes[i].indexOf('retrofit2.OkHttpCall') !== -1) {
                const OkHttpCall = Java.use('retrofit2.OkHttpCall');
                hookAllOverloads('retrofit2.OkHttpCall', 'execute', (args: any[]) => {
                    send({type: 'network', action: 'retrofit_execute', timestamp: Date.now()});
                });
                hookAllOverloads('retrofit2.OkHttpCall', 'enqueue', (args: any[]) => {
                    send({type: 'network', action: 'retrofit_enqueue', timestamp: Date.now()});
                });
                break;
            }
        }
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
    });

    // malware often loads additional DEX files at runtime to hide payloads
    hookAllOverloads('dalvik.system.DexClassLoader', '$init', (args: any[]) => {
        const dexPath = '' + args[0];
        console.log('[DEX] DexClassLoader loading: ' + dexPath);
        let javaStack = '';
        try { javaStack = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new()); } catch(e) {}
        send({type: 'api', action: 'dex_load', path: dexPath, java_backtrace: javaStack, timestamp: Date.now()});
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
        });
    } catch (e) {}

    hookAllOverloads('android.content.ContentResolver', 'query', (args: any[]) => {
        try {
            const uri = '' + args[0];
            console.log('[CONTENT] query: ' + uri);
            send({type: 'api', action: 'content_query', uri: uri, timestamp: Date.now()});
        } catch (e) {}
    });

    hookAllOverloads('android.content.ContentResolver', 'insert', (args: any[]) => {
        try {
            const uri = '' + args[0];
            console.log('[CONTENT] insert: ' + uri);
            send({type: 'api', action: 'content_insert', uri: uri, timestamp: Date.now()});
        } catch (e) {}
    });

    hookAllOverloads('java.lang.ProcessBuilder', 'start', (args: any[]) => {
        console.log('[EXEC] ProcessBuilder.start()');
        send({type: 'exec', action: 'process_builder', timestamp: Date.now()});
    });

    function _isSystemClass(className: string): boolean {
        try {
            const cls = Java.use(className);
            const loader = cls.class.getClassLoader();
            if (loader === null) return true;
            
            const loaderName = '' + loader.getClass().getName();
            if (loaderName === 'java.lang.BootClassLoader') return true;
            if (loaderName.indexOf('PathClassLoader') !== -1 ||
                loaderName.indexOf('DexClassLoader') !== -1 ||
                loaderName.indexOf('InMemoryDexClassLoader') !== -1) {

                const loaderStr = '' + loader.toString();
                if (loaderStr.indexOf('/system/') !== -1 ||
                    loaderStr.indexOf('/apex/') !== -1) return true;
                return false;
            }
            return true;  // unknown loaders treated as system to reduce noise
        } catch (e) {
            if (className.indexOf('java.lang.') === 0 ||
                className.indexOf('java.util.') === 0 ||
                className.indexOf('sun.') === 0 ||
                className.indexOf('dalvik.system.') === 0) return true;
            return false;
        }
    }

    safeJavaHook('java.lang.reflect.Method', 'invoke', (cls: any) => {
        const origInvoke = cls.invoke;
        origInvoke.overloads.forEach((overload: any) => {
            overload.implementation = function() {
                try {
                    const declaringClass = '' + this.getDeclaringClass().getName();
                    if (!_isSystemClass(declaringClass)) {
                        const mName = '' + this.getName();
                        send({type: 'api', action: 'reflect_invoke', className: declaringClass, method: mName, timestamp: Date.now()});
                    }
                } catch (e) {}
                return overload.apply(this, arguments);
            };
        });
    });

    hookAllOverloads('java.lang.Class', 'forName', (args: any[]) => {
        try {
            const className = '' + args[0];
            // filter out noise from known-safe framework classes only
            if (!_isSystemClass(className)) {
                console.log('[REFLECT] Class.forName: ' + className);
                send({type: 'api', action: 'class_forname', className: className, timestamp: Date.now()});
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

const dlopenPtr = Module.findExportByName('libc.so', 'dlopen');
const androidDlopenExtPtr = Module.findExportByName('libdl.so', 'android_dlopen_ext') ||
                            Module.findExportByName('libc.so', 'android_dlopen_ext');

const _dlopenCallbacks = {
    onEnter: function(this: any, args: any) {
        try {
            const path = args[0].readUtf8String();
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

if (dlopenPtr) {
    Interceptor.attach(dlopenPtr, _dlopenCallbacks);
    console.log('[+] dlopen watcher');
}
if (androidDlopenExtPtr) {
    Interceptor.attach(androidDlopenExtPtr, _dlopenCallbacks);
    console.log('[+] android_dlopen_ext watcher');
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
    Java.perform(() => {
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
                            // class not in this loader, try next.
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
}

setTimeout(tryDeferredHooks, 3000);
setTimeout(tryDeferredHooks, 8000);
setTimeout(tryDeferredHooks, 15000);

Java.perform(() => {
    setTimeout(() => {
        try {
            const loadedClasses = Java.enumerateLoadedClassesSync();
            let httpClientCount = 0;
            let cryptoCount = 0;

            for (let i = 0; i < loadedClasses.length; i++) {
                const cn = loadedClasses[i];
                if (cn.indexOf('java.') === 0 || cn.indexOf('android.') === 0 ||
                    cn.indexOf('androidx.') === 0 || cn.indexOf('com.google.') === 0 ||
                    cn.indexOf('dalvik.') === 0 || cn.indexOf('sun.') === 0) continue;

                try {
                    const cls = Java.use(cn);
                    const methods = cls.class.getDeclaredMethods();
                    for (let j = 0; j < methods.length; j++) {
                        const mName = methods[j].getName();
                        const mSig = methods[j].toString();

                        // detect classes implementing http client patterns
                        // (obfuscated OkHttp clones, custom http clients)
                        if ((mSig.indexOf('HttpURLConnection') !== -1 ||
                            mSig.indexOf('OutputStream') !== -1) &&
                            mName.length <= 3 && httpClientCount < 10) {
                            console.log('[SCAN] Potential obfuscated HTTP class: ' + cn + '.' + mName);
                            send({type: 'scan', action: 'obfuscated_http', className: cn, method: mName, timestamp: Date.now()});
                            httpClientCount++;
                        }

                        // detect obfuscated crypto usage
                        if ((mSig.indexOf('SecretKeySpec') !== -1 ||
                            mSig.indexOf('Cipher') !== -1 ||
                            mSig.indexOf('[B') !== -1) &&
                            mName.length <= 2 && cryptoCount < 10) {
                            console.log('[SCAN] Potential obfuscated crypto class: ' + cn + '.' + mName);
                            send({type: 'scan', action: 'obfuscated_crypto', className: cn, method: mName, timestamp: Date.now()});
                            cryptoCount++;
                        }
                    }
                } catch (e) {}
            }

            console.log('[SCAN] Class scan complete. ' +
                        'Potential obfuscated HTTP: ' + httpClientCount +
                        ', Crypto: ' + cryptoCount);
        } catch (e) {
            console.log('[-] Class scanner error: ' + e);
        }
    }, 5000);
});

console.log('[*] All hooks installed. Interact with the app to capture behavior.');
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
