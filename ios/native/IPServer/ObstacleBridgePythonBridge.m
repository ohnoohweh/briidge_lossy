#import "ObstacleBridgePythonBridge.h"

#include <Python/Python.h>
#include <unistd.h>

static NSString *const OBPythonBridgeErrorDomain = @"ObstacleBridgePythonBridge";

@implementation ObstacleBridgePythonBridge {
    dispatch_queue_t _queue;
    BOOL _initialized;
}

+ (instancetype)sharedBridge {
    static ObstacleBridgePythonBridge *sharedBridge = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedBridge = [[self alloc] initPrivate];
    });
    return sharedBridge;
}

- (instancetype)init {
    return [self initPrivate];
}

- (instancetype)initPrivate {
    self = [super init];
    if (self != nil) {
        _queue = dispatch_queue_create("com.obstaclebridge.ipserver.python", DISPATCH_QUEUE_SERIAL);
        _initialized = NO;
    }
    return self;
}

- (nullable NSDictionary *)sendMessage:(NSDictionary *)message error:(NSError **)error {
    __block NSDictionary *response = nil;
    __block NSError *localError = nil;
    NSString *command = [message[@"command"] isKindOfClass:[NSString class]] ? message[@"command"] : @"";
    NSLog(@"ObstacleBridgePythonBridge sendMessage command=%@", command);
    [self recordProviderEvent:@"python_bridge_send_message_entered" fields:@{@"command": command}];

    dispatch_sync(_queue, ^{
        if (![self ensurePythonInitialized:&localError]) {
            return;
        }

        PyGILState_STATE gilState = PyGILState_Ensure();
        @try {
            response = [self invokePythonMessage:message error:&localError];
        }
        @catch (NSException *exception) {
            localError = [NSError errorWithDomain:OBPythonBridgeErrorDomain
                                            code:90
                                        userInfo:@{
                NSLocalizedDescriptionKey: exception.reason ?: exception.name ?: @"Objective-C exception in Python bridge",
                @"exception_name": exception.name ?: @"",
                @"exception_reason": exception.reason ?: @"",
                @"exception_callstack": exception.callStackSymbols ?: @[],
            }];

            [self recordProviderEvent:@"objc_exception_in_python_bridge"
                            fields:@{
                @"name": exception.name ?: @"",
                @"reason": exception.reason ?: @"",
                @"callstack": exception.callStackSymbols ?: @[],
            }];
        }
        @finally {
            PyGILState_Release(gilState);
        }
    });

    if (error != NULL) {
        *error = localError;
    }
    if (localError != nil) {
        NSLog(@"ObstacleBridgePythonBridge sendMessage failed command=%@ error=%@", command, localError.localizedDescription);
        [self recordProviderEvent:@"python_bridge_send_message_failed" fields:@{@"command": command, @"error": localError.localizedDescription ?: @""}];
    } else {
        NSLog(@"ObstacleBridgePythonBridge sendMessage completed command=%@", command);
        [self recordProviderEvent:@"python_bridge_send_message_completed" fields:@{@"command": command}];
    }
    return response;
}

- (nullable NSDictionary *)probePythonRuntimeWithError:(NSError **)error {
    __block NSDictionary *response = nil;
    __block NSError *localError = nil;
    NSLog(@"ObstacleBridgePythonBridge probePythonRuntime");

    dispatch_sync(_queue, ^{
        if (![self ensurePythonInitialized:&localError]) {
            return;
        }

        PyGILState_STATE gilState = PyGILState_Ensure();
        @try {
            NSArray<NSString *> *modules = @[@"json", @"socket", @"asyncio", @"ssl"];
            NSMutableArray<NSString *> *imported = [NSMutableArray arrayWithCapacity:modules.count];
            for (NSString *moduleName in modules) {
                PyObject *module = PyImport_ImportModule(moduleName.UTF8String);
                if (module == NULL) {
                    localError = [self currentPythonErrorWithCode:15 fallback:[NSString stringWithFormat:@"Could not import %@", moduleName]];
                    return;
                }
                Py_DECREF(module);
                [imported addObject:moduleName];
            }
            response = @{
                @"ok": @YES,
                @"command": @"native_python_probe",
                @"imported": imported,
            };
        } @finally {
            PyGILState_Release(gilState);
        }
    });

    if (error != NULL) {
        *error = localError;
    }
    if (localError != nil) {
        NSLog(@"ObstacleBridgePythonBridge probePythonRuntime failed error=%@", localError.localizedDescription);
    } else {
        NSLog(@"ObstacleBridgePythonBridge probePythonRuntime completed");
    }
    return response;
}

- (nullable NSDictionary *)probePythonModules:(NSArray<NSString *> *)moduleNames error:(NSError **)error {
    __block NSDictionary *response = nil;
    __block NSError *localError = nil;
    NSLog(@"ObstacleBridgePythonBridge probePythonModules modules=%@", moduleNames);

    dispatch_sync(_queue, ^{
        if (![self ensurePythonInitialized:&localError]) {
            return;
        }

        PyGILState_STATE gilState = PyGILState_Ensure();
        @try {
            NSMutableArray<NSString *> *imported = [NSMutableArray arrayWithCapacity:moduleNames.count];
            for (NSString *moduleName in moduleNames) {
                PyObject *module = PyImport_ImportModule(moduleName.UTF8String);
                if (module == NULL) {
                    localError = [self currentPythonErrorWithCode:16 fallback:[NSString stringWithFormat:@"Could not import %@", moduleName]];
                    return;
                }
                Py_DECREF(module);
                [imported addObject:moduleName];
            }
            response = @{
                @"ok": @YES,
                @"command": @"obstaclebridge_module_probe",
                @"imported": imported,
            };
        } @finally {
            PyGILState_Release(gilState);
        }
    });

    if (error != NULL) {
        *error = localError;
    }
    if (localError != nil) {
        NSLog(@"ObstacleBridgePythonBridge probePythonModules failed error=%@", localError.localizedDescription);
    } else {
        NSLog(@"ObstacleBridgePythonBridge probePythonModules completed");
    }
    return response;
}

- (BOOL)ensurePythonInitialized:(NSError **)error {
    if (_initialized) {
        [self recordProviderEvent:@"python_initialize_reused" fields:@{}];
        return YES;
    }
    NSLog(@"ObstacleBridgePythonBridge initializing Python pid=%d", getpid());
    [self recordProviderEvent:@"python_initialize_requested" fields:@{@"pid": @(getpid())}];

    setenv("LANG", [[[NSString stringWithFormat:@"%@.UTF-8", NSLocale.currentLocale.localeIdentifier] stringByStandardizingPath] UTF8String], 1);
    NSURL *sharedContainerURL = [NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:@"group.com.obstaclebridge.shared"];
    if (sharedContainerURL != nil) {
        setenv("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", sharedContainerURL.path.UTF8String, 1);
        NSString *bridgeImportDebugPath = [[sharedContainerURL.path stringByAppendingPathComponent:@"logs"] stringByAppendingPathComponent:@"ipserver-python-import-debug.jsonl"];
        setenv("OBSTACLEBRIDGE_BRIDGE_IMPORT_DEBUG_LOG", bridgeImportDebugPath.UTF8String, 1);
        NSLog(@"ObstacleBridgePythonBridge using shared documents root=%@", sharedContainerURL.path);
        [self recordProviderEvent:@"python_shared_documents_root_resolved"
                           fields:@{
            @"path": sharedContainerURL.path ?: @"",
            @"bridge_import_debug_log": bridgeImportDebugPath ?: @"",
        }];
    }

    NSBundle *extensionBundle = [NSBundle mainBundle];
    NSURL *plugInsURL = [extensionBundle.bundleURL URLByDeletingLastPathComponent];
    NSURL *appBundleURL = [plugInsURL URLByDeletingLastPathComponent];
    NSBundle *appBundle = [NSBundle bundleWithURL:appBundleURL];
    NSString *resourcePath = appBundle.resourcePath;
    if (resourcePath.length == 0) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain code:1 userInfo:@{NSLocalizedDescriptionKey: @"Unable to resolve containing app resource path"}];
        }
        [self recordProviderEvent:@"python_resource_path_failed" fields:@{}];
        return NO;
    }
    [self recordProviderEvent:@"python_resource_path_resolved" fields:@{@"resource_path": resourcePath}];

    PyStatus status;
    PyPreConfig preconfig;
    PyConfig config;
    wchar_t *wide = NULL;

    PyPreConfig_InitIsolatedConfig(&preconfig);
    PyConfig_InitIsolatedConfig(&config);
    preconfig.utf8_mode = 1;
    preconfig.configure_locale = 1;
    config.buffered_stdio = 0;
    config.write_bytecode = 0;
    config.module_search_paths_set = 1;

    status = Py_PreInitialize(&preconfig);
    if (PyStatus_Exception(status)) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain code:2 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Py_PreInitialize failed: %s", status.err_msg]}];
        }
        [self recordProviderEvent:@"python_preinitialize_failed" fields:@{@"error": [NSString stringWithFormat:@"%s", status.err_msg ?: "unknown"]}];
        PyConfig_Clear(&config);
        return NO;
    }
    [self recordProviderEvent:@"python_preinitialize_completed" fields:@{}];

    NSString *pythonHome = [resourcePath stringByAppendingPathComponent:@"python"];
    wide = Py_DecodeLocale(pythonHome.UTF8String, NULL);
    status = PyConfig_SetString(&config, &config.home, wide);
    PyMem_RawFree(wide);
    if (PyStatus_Exception(status)) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain code:3 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Unable to set PYTHONHOME: %s", status.err_msg]}];
        }
        [self recordProviderEvent:@"python_home_config_failed" fields:@{@"error": [NSString stringWithFormat:@"%s", status.err_msg ?: "unknown"]}];
        PyConfig_Clear(&config);
        return NO;
    }
    [self recordProviderEvent:@"python_home_configured" fields:@{@"python_home": pythonHome}];

    status = PyConfig_Read(&config);
    if (PyStatus_Exception(status)) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain code:4 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"PyConfig_Read failed: %s", status.err_msg]}];
        }
        [self recordProviderEvent:@"python_config_read_failed" fields:@{@"error": [NSString stringWithFormat:@"%s", status.err_msg ?: "unknown"]}];
        PyConfig_Clear(&config);
        return NO;
    }
    [self recordProviderEvent:@"python_config_read_completed" fields:@{}];

    NSArray<NSString *> *paths = @[
        [resourcePath stringByAppendingPathComponent:@"python/lib/python3.14"],
        [resourcePath stringByAppendingPathComponent:@"python/lib/python3.14/lib-dynload"],
        [resourcePath stringByAppendingPathComponent:@"app"],
    ];
    for (NSString *path in paths) {
        wide = Py_DecodeLocale(path.UTF8String, NULL);
        status = PyWideStringList_Append(&config.module_search_paths, wide);
        PyMem_RawFree(wide);
        if (PyStatus_Exception(status)) {
            if (error != NULL) {
                *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain code:5 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Unable to append Python path %@: %s", path, status.err_msg]}];
            }
            [self recordProviderEvent:@"python_module_path_append_failed" fields:@{@"path": path, @"error": [NSString stringWithFormat:@"%s", status.err_msg ?: "unknown"]}];
            PyConfig_Clear(&config);
            return NO;
        }
        [self recordProviderEvent:@"python_module_path_appended" fields:@{@"path": path}];
    }

    int argc = 0;
    status = PyConfig_SetBytesArgv(&config, argc, NULL);
    if (PyStatus_Exception(status)) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain code:6 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Unable to configure argv: %s", status.err_msg]}];
        }
        [self recordProviderEvent:@"python_argv_config_failed" fields:@{@"error": [NSString stringWithFormat:@"%s", status.err_msg ?: "unknown"]}];
        PyConfig_Clear(&config);
        return NO;
    }
    [self recordProviderEvent:@"python_argv_configured" fields:@{}];

    status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    if (PyStatus_Exception(status)) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain code:7 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Py_InitializeFromConfig failed: %s", status.err_msg]}];
        }
        [self recordProviderEvent:@"python_initialize_failed" fields:@{@"error": [NSString stringWithFormat:@"%s", status.err_msg ?: "unknown"]}];
        return NO;
    }
    [self recordProviderEvent:@"python_initialize_completed" fields:@{}];

    NSString *nslogPath = [resourcePath stringByAppendingPathComponent:@"app_packages/nslog.py"];
    FILE *fd = fopen(nslogPath.UTF8String, "r");
    if (fd != NULL) {
        PyRun_SimpleFileEx(fd, nslogPath.UTF8String, 1);
        [self recordProviderEvent:@"python_nslog_loaded" fields:@{@"path": nslogPath}];
    } else {
        [self recordProviderEvent:@"python_nslog_missing" fields:@{@"path": nslogPath}];
    }

    PyObject *siteModule = PyImport_ImportModule("site");
    if (siteModule == NULL) {
        if (error != NULL) {
            *error = [self currentPythonErrorWithCode:8 fallback:@"Could not import Python site module"];
        }
        [self recordProviderEvent:@"python_site_import_failed" fields:@{@"error": (*error).localizedDescription ?: @""}];
        return NO;
    }
    [self recordProviderEvent:@"python_site_imported" fields:@{}];

    PyObject *addSiteDir = PyObject_GetAttrString(siteModule, "addsitedir");
    if (addSiteDir == NULL || !PyCallable_Check(addSiteDir)) {
        Py_XDECREF(addSiteDir);
        Py_DECREF(siteModule);
        if (error != NULL) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain code:9 userInfo:@{NSLocalizedDescriptionKey: @"Could not access site.addsitedir"}];
        }
        [self recordProviderEvent:@"python_addsitedir_missing" fields:@{}];
        return NO;
    }

    NSString *appPackagesPath = [resourcePath stringByAppendingPathComponent:@"app_packages"];
    wide = Py_DecodeLocale(appPackagesPath.UTF8String, NULL);
    PyObject *pathObject = PyUnicode_FromWideChar(wide, wcslen(wide));
    PyMem_RawFree(wide);
    PyObject *args = Py_BuildValue("(O)", pathObject);
    PyObject *result = PyObject_CallObject(addSiteDir, args);
    Py_XDECREF(result);
    Py_DECREF(args);
    Py_DECREF(pathObject);
    Py_DECREF(addSiteDir);
    Py_DECREF(siteModule);
    if (result == NULL) {
        if (error != NULL) {
            *error = [self currentPythonErrorWithCode:10 fallback:@"Could not add app_packages to site directories"];
        }
        [self recordProviderEvent:@"python_app_packages_add_failed" fields:@{@"path": appPackagesPath, @"error": (*error).localizedDescription ?: @""}];
        return NO;
    }
    [self recordProviderEvent:@"python_app_packages_added" fields:@{@"path": appPackagesPath}];

    [self installPythonDebugHooks];

    PyEval_SaveThread();
    _initialized = YES;
    NSLog(@"ObstacleBridgePythonBridge initialized Python resourcePath=%@", resourcePath);
    [self recordProviderEvent:@"python_runtime_ready" fields:@{@"resource_path": resourcePath}];
    return YES;
}

- (NSString *)pythonStringLiteral:(NSString *)value {
    NSMutableString *out = [NSMutableString stringWithString:@"\""];

    NSString *s = value ?: @"";
    for (NSUInteger i = 0; i < s.length; i++) {
        unichar c = [s characterAtIndex:i];

        switch (c) {
            case '\\':
                [out appendString:@"\\\\"];
                break;
            case '"':
                [out appendString:@"\\\""];
                break;
            case '\n':
                [out appendString:@"\\n"];
                break;
            case '\r':
                [out appendString:@"\\r"];
                break;
            case '\t':
                [out appendString:@"\\t"];
                break;
            default:
                if (c < 0x20) {
                    [out appendFormat:@"\\u%04x", c];
                } else {
                    [out appendFormat:@"%C", c];
                }
                break;
        }
    }

    [out appendString:@"\""];
    return out;
}

- (nullable NSDictionary *)invokePythonMessage:(NSDictionary *)message error:(NSError **)error {
    NSData *messageData = [NSJSONSerialization dataWithJSONObject:message options:0 error:error];
    if (messageData == nil) {
        return nil;
    }

    NSString *messageJSON = [[NSString alloc] initWithData:messageData encoding:NSUTF8StringEncoding];

    NSString *packageName = @"obstacle_bridge_ios";
    NSString *moduleName = @"obstacle_bridge_ios.ipserver_extension";
    //NSString *moduleName = @"ipserver_import_probe";

    NSString *code = [NSString stringWithFormat:
        @"import importlib, traceback, json, os, time, sys\n"
        "root=os.environ.get('OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT','')\n"
        "p=os.environ.get('OBSTACLEBRIDGE_BRIDGE_IMPORT_DEBUG_LOG') or os.path.join(root,'logs','ipserver-python-import-debug.jsonl')\n"
        "def log(event, **kw):\n"
        "    try:\n"
        "        os.makedirs(os.path.dirname(p), exist_ok=True)\n"
        "        with open(p,'a',encoding='utf-8') as f:\n"
        "            f.write(json.dumps({'event':event,'time':time.time(),**kw}, sort_keys=True)+'\\n')\n"
        "            f.flush()\n"
        "    except BaseException:\n"
        "        pass\n"
        "def probe(name):\n"
        "    log('probe_import_before', module=name)\n"
        "    try:\n"
        "        m = importlib.import_module(name)\n"
        "        log('probe_import_after', module=name, file=getattr(m, '__file__', ''), package=getattr(m, '__package__', ''))\n"
        "        return m\n"
        "    except BaseException as e:\n"
        "        log('probe_import_exception', module=name, error=repr(e), traceback=traceback.format_exc())\n"
        "        raise\n"
        "log('sys_path_snapshot', path=sys.path)\n"
        "probe('json')\n"
        "probe('os')\n"
        "probe('socket')\n"
        "probe('asyncio')\n"
        "probe('obstacle_bridge')\n"
        "probe('obstacle_bridge.bridge')\n"
        "probe('obstacle_bridge.packet_io')\n"
        "probe('obstacle_bridge.core')\n"
        "__ob_package =probe('src.%@')\n"
        "__ob_module = probe('src.%@')\n",
        packageName,
        moduleName
   ];

    PyObject *globals = PyDict_New();
    if (globals == NULL) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain
                                         code:21
                                     userInfo:@{NSLocalizedDescriptionKey: @"Could not allocate Python globals"}];
        }
        return nil;
    }

    PyDict_SetItemString(globals, "__builtins__", PyEval_GetBuiltins());

    [self recordProviderEvent:@"python_entry_module_import_wrapper_before"
                       fields:@{@"module": moduleName}];

    PyObject *importResult = PyRun_String(code.UTF8String, Py_file_input, globals, globals);

    [self recordProviderEvent:@"python_entry_module_import_wrapper_after"
                       fields:@{
                           @"module": moduleName,
                           @"result_null": @(importResult == NULL),
                           @"python_error_present": @(PyErr_Occurred() != NULL),
                       }];

    if (importResult == NULL) {
        Py_DECREF(globals);
        if (error != NULL) {
            *error = [self currentPythonErrorWithCode:11 fallback:@"Python import wrapper failed"];
        }
        return nil;
    }
    Py_DECREF(importResult);

    PyObject *module = PyDict_GetItemString(globals, "__ob_module");  // borrowed
    if (module == NULL) {
        Py_DECREF(globals);
        if (error != NULL) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain
                                         code:22
                                     userInfo:@{NSLocalizedDescriptionKey: @"Python import wrapper did not set __ob_module"}];
        }
        [self recordProviderEvent:@"python_entry_module_missing_after_wrapper" fields:@{}];
        return nil;
    }

    Py_INCREF(module);
    Py_DECREF(globals);

    [self recordProviderEvent:@"python_entry_module_imported" fields:@{@"module": moduleName}];

    PyObject *callable = PyObject_GetAttrString(module, "handle_message_json");
    if (callable == NULL || !PyCallable_Check(callable)) {
        Py_XDECREF(callable);
        Py_DECREF(module);
        if (error != NULL) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain
                                         code:12
                                     userInfo:@{NSLocalizedDescriptionKey: @"Python entrypoint handle_message_json is missing"}];
        }
        [self recordProviderEvent:@"python_entry_callable_missing" fields:@{}];
        return nil;
    }

    [self recordProviderEvent:@"python_entry_callable_resolved" fields:@{}];

    PyObject *args = Py_BuildValue("(s)", messageJSON.UTF8String);
    PyObject *callResult = PyObject_CallObject(callable, args);

    Py_DECREF(args);
    Py_DECREF(callable);
    Py_DECREF(module);

    if (callResult == NULL) {
        if (error != NULL) {
            *error = [self currentPythonErrorWithCode:13 fallback:@"Python command execution failed"];
        }
        [self recordProviderEvent:@"python_entry_call_failed"
                           fields:@{@"error": error != NULL && *error != nil ? (*error).localizedDescription : @""}];
        return nil;
    }

    [self recordProviderEvent:@"python_entry_call_completed" fields:@{}];

    const char *resultCString = PyUnicode_AsUTF8(callResult);
    if (resultCString == NULL) {
        Py_DECREF(callResult);
        if (error != NULL) {
            *error = [self currentPythonErrorWithCode:14 fallback:@"Python response was not UTF-8 text"];
        }
        [self recordProviderEvent:@"python_response_utf8_failed" fields:@{}];
        return nil;
    }

    NSString *resultJSON = [NSString stringWithUTF8String:resultCString];
    if (resultJSON == nil) {
        resultJSON = @"{}";
    }
    Py_DECREF(callResult);

    NSData *resultData = [resultJSON dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *payload = [NSJSONSerialization JSONObjectWithData:resultData options:0 error:error];

    if (![payload isKindOfClass:[NSDictionary class]]) {
        if (error != NULL && *error == nil) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain
                                         code:14
                                     userInfo:@{NSLocalizedDescriptionKey: @"Python response was not a JSON object"}];
        }
        [self recordProviderEvent:@"python_response_decode_failed" fields:@{}];
        return nil;
    }

    [self recordProviderEvent:@"python_response_decoded"
                       fields:@{@"keys": payload.allKeys ?: @[]}];

    return payload;
}

- (void)installPythonDebugHooks {
    const char *code =
        "import os, sys, faulthandler, traceback, json, time\n"
        "root = os.environ.get('OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT', '')\n"
        "logdir = os.path.join(root, 'logs') if root else '/tmp'\n"
        "os.makedirs(logdir, exist_ok=True)\n"
        "path = os.path.join(logdir, 'ipserver-python-faulthandler.log')\n"
        "f = open(path, 'a', buffering=1)\n"
        "sys.stderr = f\n"
        "sys.stdout = f\n"
        "faulthandler.enable(file=f, all_threads=True)\n"
        "print('PYTHON_DEBUG_HOOKS_INSTALLED', time.time(), flush=True)\n";

    PyObject *globals = PyDict_New();
    if (globals == NULL) {
        [self recordProviderEvent:@"python_debug_hooks_globals_failed" fields:@{}];
        return;
    }

    PyDict_SetItemString(globals, "__builtins__", PyEval_GetBuiltins());

    PyObject *result = PyRun_String(code, Py_file_input, globals, globals);
    Py_DECREF(globals);

    if (result == NULL) {
        [self recordProviderEvent:@"python_debug_hooks_failed"
                           fields:@{@"python_error_present": @(PyErr_Occurred() != NULL)}];
        PyErr_Clear();
        return;
    }

    Py_DECREF(result);
    [self recordProviderEvent:@"python_debug_hooks_installed" fields:@{}];
}

- (NSError *)currentPythonErrorWithCode:(NSInteger)code fallback:(NSString *)fallback {
    NSMutableDictionary *logFields = [@{
        @"code": @(code),
        @"fallback": fallback ?: @"",
        @"python_error_present": @(PyErr_Occurred() != NULL)
    } mutableCopy];

    if (!PyErr_Occurred()) {
        [self recordProviderEvent:@"python_error_missing"
                           fields:logFields];

        return [NSError errorWithDomain:OBPythonBridgeErrorDomain
                                   code:code
                               userInfo:@{NSLocalizedDescriptionKey: fallback ?: @"Python error"}];
    }

    PyObject *type = NULL;
    PyObject *value = NULL;
    PyObject *traceback = NULL;

    PyErr_Fetch(&type, &value, &traceback);
    PyErr_NormalizeException(&type, &value, &traceback);

    NSString *message = fallback ?: @"Python error";
    NSString *exceptionType = nil;
    NSString *tracebackString = nil;

    if (type != NULL) {
        PyObject *typeName = PyObject_GetAttrString(type, "__name__");
        if (typeName != NULL) {
            const char *utf8 = PyUnicode_AsUTF8(typeName);
            if (utf8 != NULL) {
                exceptionType = [NSString stringWithUTF8String:utf8];
            }
            Py_DECREF(typeName);
        }
    }

    if (value != NULL) {
        PyObject *stringObject = PyObject_Str(value);
        if (stringObject != NULL) {
            const char *utf8 = PyUnicode_AsUTF8(stringObject);
            if (utf8 != NULL) {
                message = [NSString stringWithUTF8String:utf8];
            } else {
                logFields[@"message_conversion_failed"] = @YES;
            }
            Py_DECREF(stringObject);
        } else {
            logFields[@"message_str_failed"] = @YES;
        }
    }

    if (traceback != NULL) {
        PyObject *tracebackModule = PyImport_ImportModule("traceback");
        if (tracebackModule != NULL) {
            PyObject *formatException = PyObject_GetAttrString(tracebackModule, "format_exception");

            if (formatException != NULL) {
                PyObject *formatted = PyObject_CallFunctionObjArgs(
                    formatException,
                    type ? type : Py_None,
                    value ? value : Py_None,
                    traceback,
                    NULL
                );

                if (formatted != NULL) {
                    PyObject *separator = PyUnicode_FromString("");
                    if (separator != NULL) {
                        PyObject *joined = PyUnicode_Join(separator, formatted);
                        if (joined != NULL) {
                            const char *utf8 = PyUnicode_AsUTF8(joined);
                            if (utf8 != NULL) {
                                tracebackString = [NSString stringWithUTF8String:utf8];
                            }
                            Py_DECREF(joined);
                        }
                        Py_DECREF(separator);
                    }
                    Py_DECREF(formatted);
                }

                Py_DECREF(formatException);
            }

            Py_DECREF(tracebackModule);
        }
    }

    logFields[@"message"] = message ?: @"";
    if (exceptionType.length > 0) {
        logFields[@"python_exception_type"] = exceptionType;
    }
    if (tracebackString.length > 0) {
        logFields[@"python_traceback"] = tracebackString;
    }

    [self recordProviderEvent:@"python_error"
                       fields:logFields];

    Py_XDECREF(type);
    Py_XDECREF(value);
    Py_XDECREF(traceback);

    return [NSError errorWithDomain:OBPythonBridgeErrorDomain
                               code:code
                           userInfo:@{
                               NSLocalizedDescriptionKey: message ?: fallback ?: @"Python error",
                               @"OBPythonExceptionType": exceptionType ?: @"",
                               @"OBPythonTraceback": tracebackString ?: @""
                           }];
}

- (NSURL *)providerLogURL {
    NSURL *sharedContainerURL = [NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:@"group.com.obstaclebridge.shared"];
    if (sharedContainerURL == nil) {
        return nil;
    }
    NSURL *logDirectory = [sharedContainerURL URLByAppendingPathComponent:@"logs" isDirectory:YES];
    [NSFileManager.defaultManager createDirectoryAtURL:logDirectory withIntermediateDirectories:YES attributes:nil error:nil];
    return [logDirectory URLByAppendingPathComponent:@"ipserver-native-provider.jsonl"];
}

- (void)recordProviderEvent:(NSString *)event fields:(NSDictionary *)fields {
    NSURL *logURL = [self providerLogURL];
    if (logURL == nil || event.length == 0) {
        return;
    }
    NSMutableDictionary *payload = [NSMutableDictionary dictionaryWithDictionary:fields ?: @{}];
    payload[@"native_event"] = event;
    payload[@"source"] = @"objc";
    payload[@"pid"] = @(getpid());
    payload[@"timestamp"] = [[NSISO8601DateFormatter new] stringFromDate:[NSDate date]];
    if (![NSJSONSerialization isValidJSONObject:payload]) {
        return;
    }
    NSData *data = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
    if (data == nil) {
        return;
    }
    NSString *line = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (line == nil) {
        return;
    }
    NSData *lineData = [[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:logURL.path];
    if (handle != nil) {
        @try {
            [handle seekToEndOfFile];
            [handle writeData:lineData];
        } @catch (__unused NSException *exception) {
        } @finally {
            @try {
                [handle closeFile];
            } @catch (__unused NSException *exception) {
            }
        }
        return;
    }
    [lineData writeToURL:logURL atomically:YES];
}

@end
