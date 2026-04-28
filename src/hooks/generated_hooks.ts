// auto-generated hooks with resilient instrumentation
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

console.log('[*] Detected frameworks: native');

// (global) prevents hook errors from crashing the app
Process.setExceptionHandler(function(details: any) {
    console.log('[!] Exception in ' + details.type + ' at ' + details.address +
                ' context: ' + JSON.stringify(details.context));
    return true; // suppress the exception, keep the process alive
});

// safe hook wrapper; catches errors per-hook so one
// failing hook does not prevent others from installing
function safeJavaHook(className: string, methodName: string, hookFn: (cls: any) => void) {
    try {
        const cls = Java.use(className);
        hookFn(cls);
        console.log('[+] Hooked ' + className + '.' + methodName);
    } catch (e) {
        console.log('[-] Failed to hook ' + className + '.' + methodName + ': ' + e);
    }
}

// hook "all" overloads of a method safely
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
            // module not yet loaded, will be caught by dlopen watcher
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

const _hookedNative: any = {};  // track which native funcs we already hooked
const _hookedClasses: any = {}; // track which Java classes we already hooked

// ============================================================
// anti-detection bypass: Root, Frida, and SSL pinning
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
        send({type: 'exec', action: 'runtime_exec', command: cmdStr, timestamp: Date.now()});
    });

    // apps detect frida by scanning /proc/self/maps for frida-agent, checking
    // default frida port 27042, or scanning for frida-server in process list.

    // block reading /proc/self/maps; detect injected libraries
    safeJavaHook('java.io.BufferedReader', 'readLine', (cls: any) => {
        const origReadLine = cls.readLine.overloads[0];
        origReadLine.implementation = function() {
            const line = origReadLine.call(this);
            if (line !== null) {
                const lineStr = line.toString();
                if (lineStr.indexOf('frida') !== -1 || lineStr.indexOf('gadget') !== -1 ||
                    lineStr.indexOf('gmain') !== -1 || lineStr.indexOf('linjector') !== -1) {
                    console.log('[BYPASS] /proc/maps frida detection line hidden');
                    send({type: 'bypass', action: 'frida_maps_hide', timestamp: Date.now()});
                    return origReadLine.call(this);
                }
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

    // bypass android NetworkSecurityConfig for API 24+
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

    hookAllOverloads('java.net.URL', '$init', (args: any[]) => {
        try {
            if (args.length >= 1) {
                const url = '' + args[0];
                send({type: 'network', action: 'url_init', url: url, timestamp: Date.now()});
            }
        } catch (e) {}
    });

    console.log('[+] Java network hooks');
});

console.log('[*] Installing native hooks.');

// prevents frida message-queue overload on high-freq hooks
const _ipcBuffer: any[] = [];
const IPC_FLUSH_MS = 300;
const IPC_MAX_SIZE = 80;
function bufferedSend(evt: any) {
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
                        if (path && !path.includes('/dev/') && !path.includes('/proc/') && !path.includes('/sys/')) {
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
                        bufferedSend({type: 'network', action: 'connect', ip: ip, port: port, timestamp: Date.now()});
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
                        bufferedSend({type: 'network', action: 'connect', ip: ip, port: port, timestamp: Date.now()});
                    }
                } catch (e) {}
            }
        });
    }

    // Network: send/recv — capture first 128 bytes of payload for C2 fingerprinting
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

// SSL hooks
const ssl_functions = ['SSL_read', 'SSL_write', 'SSL_connect'];
const libssl = Process.getModuleByName('libssl.so');
if (libssl) {
    for (const funcName of ssl_functions) {
        const funcPtr = libssl.findExportByName(funcName);
        if (funcPtr) {
            Interceptor.attach(funcPtr, {
                onEnter: function(args: any) {
                    bufferedSend({type: 'ssl', func: funcName, timestamp: Date.now()});
                }
            });
        }
    }
}

const libart = Process.findModuleByName('libart.so');
if (libart) {
    const RegisterNatives = libart.enumerateSymbols().find((s: any) => s.name.includes('RegisterNatives'));
    if (RegisterNatives) {
        Interceptor.attach(RegisterNatives.address, {
            onEnter: function(args: any) {
                const env = args[0];
                const jclass = args[1];
                const methods = args[2];
                const nMethods = args[3].toInt32();
                try {
                    console.log(`[JNI] RegisterNatives count=${nMethods}`);
                    bufferedSend({type: 'native', action: 'jni_register', count: nMethods, timestamp: Date.now()});
                    for (let i = 0; i < nMethods; i++) {
                        const method = methods.add(i * Process.pointerSize * 3);
                        const name = method.readPointer().readUtf8String();
                        const sig = method.add(Process.pointerSize).readPointer().readUtf8String();
                        const fnPtr = method.add(Process.pointerSize * 2).readPointer();
                        
                        console.log(`  - ${name}${sig} -> ${fnPtr}`);
                        send({
                            type: 'native', 
                            action: 'jni_method_map', 
                            method: name, 
                            sig: sig, 
                            ptr: fnPtr.toString(),
                            timestamp: Date.now()
                        });
                    }
                } catch (e) {
                    console.log(`[JNI] Error in RegisterNatives hook: ${e}`);
                }
            }
        });
    }
}

console.log('[*] Native hooks installed. Interact with the app to see activity.');

console.log('[*] Installing Crypto hooks.');
Java.perform(() => {
    // Hook ALL overloads of Cipher.doFinal - not just [B
    // Obfuscated apps may call different overloads
    hookAllOverloads('javax.crypto.Cipher', 'doFinal', (args: any[], method: string, sig: string) => {
        try {
            send({type: 'crypto', action: 'cipher_dofinal', overload: sig, timestamp: Date.now()});
        } catch (e) {}
    });

    // Hook Cipher.getInstance to capture the transformation/algorithm
    hookAllOverloads('javax.crypto.Cipher', 'getInstance', (args: any[], method: string, sig: string) => {
        try {
            const transformation = '' + args[0];
            console.log('[Crypto] Cipher.getInstance(' + transformation + ')');
            send({type: 'crypto', action: 'cipher_getinstance', transformation: transformation, timestamp: Date.now()});
        } catch (e) {}
    });

    // Hook ALL overloads of MessageDigest.digest
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

    // SecretKeySpec - captures encryption keys being created
    hookAllOverloads('javax.crypto.spec.SecretKeySpec', '$init', (args: any[], method: string, sig: string) => {
        try {
            const algo = '' + args[1];
            console.log('[Crypto] SecretKeySpec created for: ' + algo);
            send({type: 'crypto', action: 'secret_key', algorithm: algo, timestamp: Date.now()});
        } catch (e) {}
    });

    // KeyGenerator
    hookAllOverloads('javax.crypto.KeyGenerator', 'getInstance', (args: any[], method: string, sig: string) => {
        try {
            const algo = '' + args[0];
            console.log('[Crypto] KeyGenerator.getInstance(' + algo + ')');
            send({type: 'crypto', action: 'keygen', algorithm: algo, timestamp: Date.now()});
        } catch (e) {}
    });

    console.log('[+] Crypto hooks');
});

console.log('[*] Installing Android API hooks.');
Java.perform(() => {
    // SMS - hook all overloads (sendTextMessage, sendMultipartTextMessage, sendDataMessage)
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

    // Location - hook all overloads
    hookAllOverloads('android.location.LocationManager', 'getLastKnownLocation', (args: any[]) => {
        const provider = '' + args[0];
        console.log('[Location] getLastKnownLocation(' + provider + ')');
        send({type: 'api', action: 'location_get', provider: provider, timestamp: Date.now()});
    });

    hookAllOverloads('android.location.LocationManager', 'requestLocationUpdates', (args: any[]) => {
        console.log('[Location] requestLocationUpdates()');
        send({type: 'api', action: 'location_updates', timestamp: Date.now()});
    });

    // Package enumeration
    hookAllOverloads('android.app.ApplicationPackageManager', 'getInstalledPackages', (args: any[]) => {
        console.log('[API] getInstalledPackages()');
        send({type: 'api', action: 'package_list', timestamp: Date.now()});
    });

    hookAllOverloads('android.app.ApplicationPackageManager', 'getInstalledApplications', (args: any[]) => {
        console.log('[API] getInstalledApplications()');
        send({type: 'api', action: 'app_list', timestamp: Date.now()});
    });

    // TelephonyManager - device info exfiltration
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

    // WiFi info
    hookAllOverloads('android.net.wifi.WifiInfo', 'getMacAddress', (args: any[]) => {
        console.log('[SYSTEM] WifiInfo.getMacAddress()');
        send({type: 'system', action: 'get_mac_address', timestamp: Date.now()});
    });

    // Contacts - data theft
    hookAllOverloads('android.provider.ContactsContract$Contacts', 'getLookupUri', (args: any[]) => {
        console.log('[API] ContactsContract access');
        send({type: 'api', action: 'contacts_access', timestamp: Date.now()});
    });
});

console.log('[*] Installing modern Android hooks.');
Java.perform(() => {
    // Retrofit; used by most modern apps for REST APIs.
    // hook at the ServiceMethod level to catch all API calls regardless of
    // how the interface is defined (obfuscation-resistant)
    try {
        const classes = Java.enumerateLoadedClassesSync();
        for (let i = 0; i < classes.length; i++) {
            // Retrofit2 OkHttp integration
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
        send({type: 'api', action: 'dex_load', path: dexPath, timestamp: Date.now()});
    });

    hookAllOverloads('dalvik.system.PathClassLoader', '$init', (args: any[]) => {
        const dexPath = '' + args[0];
        console.log('[DEX] PathClassLoader loading: ' + dexPath);
        send({type: 'api', action: 'path_classloader', path: dexPath, timestamp: Date.now()});
    });

    try {
        // API 26+ (InMemoryDexClassLoader), malware loads dex from byte array
        const InMemoryDex = Java.use('dalvik.system.InMemoryDexClassLoader');
        hookAllOverloads('dalvik.system.InMemoryDexClassLoader', '$init', (args: any[]) => {
            console.log('[DEX] InMemoryDexClassLoader - dex loaded from memory!');
            send({type: 'api', action: 'inmemory_dex_load', timestamp: Date.now()});
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

    // obfuscated malware uses reflection to call APIs.
    // this is critical: if an app uses Class.forName + Method.invoke,
    // the direct hooks on the target class won't fire. catch it here.
    hookAllOverloads('java.lang.reflect.Method', 'invoke', (args: any[]) => {
        try {
            const methodObj = args[0];
        } catch (e) {}
    });

    hookAllOverloads('java.lang.Class', 'forName', (args: any[]) => {
        try {
            const className = '' + args[0];
            // filter out noise from common framework classes
            if (className.indexOf('android.') !== 0 && className.indexOf('java.') !== 0 &&
                className.indexOf('androidx.') !== 0 && className.indexOf('com.google.') !== 0) {
                console.log('[REFLECT] Class.forName: ' + className);
                send({type: 'api', action: 'class_forname', className: className, timestamp: Date.now()});
            }
        } catch (e) {}
    });

    // check camera access
    safeJavaHook('android.hardware.Camera', 'open', (cls: any) => {
        hookAllOverloads('android.hardware.Camera', 'open', (args: any[]) => {
            console.log('[API] Camera.open()');
            send({type: 'api', action: 'camera_open', timestamp: Date.now()});
        });
    });

    // check audiorecord; microphone
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

console.log('[*] Installing dlopen watcher.');
function installSSLHooksForModule(moduleName: string) {
    if (_hookedNative['ssl_' + moduleName]) return;
    try {
        const mod = Process.findModuleByName(moduleName);
        if (!mod) return;
        const sslFuncs = ['SSL_read', 'SSL_write', 'SSL_connect'];
        for (const funcName of sslFuncs) {
            const funcPtr = mod.findExportByName(funcName);
            if (funcPtr) {
                Interceptor.attach(funcPtr, {
                    onEnter: function(args: any) {
                        bufferedSend({type: 'ssl', func: funcName, module: moduleName, timestamp: Date.now()});
                    }
                });
            }
        }
        _hookedNative['ssl_' + moduleName] = true;
        console.log('[+] Late SSL hooks for ' + moduleName);
    } catch (e) {}
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
            }
        } catch (e) {}
    },
    onLeave: function(this: any, retval: any) {
        if (!this._dlopenPath) return;
        const path = this._dlopenPath;
        const libName = path.split('/').pop();

        bufferedSend({type: 'native', action: 'dlopen', path: path, library: libName, timestamp: Date.now()});
        setTimeout(() => { scanStaticJniExports(path); }, 50);

        if (libName && (libName.indexOf('ssl') !== -1 || libName.indexOf('crypto') !== -1)) {
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
                    (Java.classFactory as any).loader = loader;
                    for (const className in DEFERRED_TARGETS) {
                        const target = DEFERRED_TARGETS[className];
                        if (target.hooked) continue;
                        try {
                            const cls = Java.use(className);
                            for (const methodName of target.methods) {
                                hookAllOverloads(className, methodName, target.callback);
                            }
                            target.hooked = true;
                            console.log('[DEFERRED] Late-hooked ' + className);
                            send({type: 'hook', action: 'deferred_success', className: className, timestamp: Date.now()});
                        } catch (e) {
                            // ok
                        }
                    }
                } catch (e) {}
            },
            onComplete: function() {}
        });

        try {
            (Java.classFactory as any).loader = null;
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
