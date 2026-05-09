#import "ObstacleBridgePythonBridge.h"

#include <Python/Python.h>

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

    dispatch_sync(_queue, ^{
        if (![self ensurePythonInitialized:&localError]) {
            return;
        }

        PyGILState_STATE gilState = PyGILState_Ensure();
        @try {
            response = [self invokePythonMessage:message error:&localError];
        } @finally {
            PyGILState_Release(gilState);
        }
    });

    if (error != NULL) {
        *error = localError;
    }
    return response;
}

- (BOOL)ensurePythonInitialized:(NSError **)error {
    if (_initialized) {
        return YES;
    }

    setenv("LANG", [[[NSString stringWithFormat:@"%@.UTF-8", NSLocale.currentLocale.localeIdentifier] stringByStandardizingPath] UTF8String], 1);

    NSBundle *extensionBundle = [NSBundle mainBundle];
    NSURL *plugInsURL = [extensionBundle.bundleURL URLByDeletingLastPathComponent];
    NSURL *appBundleURL = [plugInsURL URLByDeletingLastPathComponent];
    NSBundle *appBundle = [NSBundle bundleWithURL:appBundleURL];
    NSString *resourcePath = appBundle.resourcePath;
    if (resourcePath.length == 0) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain code:1 userInfo:@{NSLocalizedDescriptionKey: @"Unable to resolve containing app resource path"}];
        }
        return NO;
    }

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
        PyConfig_Clear(&config);
        return NO;
    }

    NSString *pythonHome = [resourcePath stringByAppendingPathComponent:@"python"];
    wide = Py_DecodeLocale(pythonHome.UTF8String, NULL);
    status = PyConfig_SetString(&config, &config.home, wide);
    PyMem_RawFree(wide);
    if (PyStatus_Exception(status)) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain code:3 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Unable to set PYTHONHOME: %s", status.err_msg]}];
        }
        PyConfig_Clear(&config);
        return NO;
    }

    status = PyConfig_Read(&config);
    if (PyStatus_Exception(status)) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain code:4 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"PyConfig_Read failed: %s", status.err_msg]}];
        }
        PyConfig_Clear(&config);
        return NO;
    }

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
            PyConfig_Clear(&config);
            return NO;
        }
    }

    int argc = 0;
    status = PyConfig_SetBytesArgv(&config, argc, NULL);
    if (PyStatus_Exception(status)) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain code:6 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Unable to configure argv: %s", status.err_msg]}];
        }
        PyConfig_Clear(&config);
        return NO;
    }

    status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    if (PyStatus_Exception(status)) {
        if (error != NULL) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain code:7 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Py_InitializeFromConfig failed: %s", status.err_msg]}];
        }
        return NO;
    }

    NSString *nslogPath = [resourcePath stringByAppendingPathComponent:@"app_packages/nslog.py"];
    FILE *fd = fopen(nslogPath.UTF8String, "r");
    if (fd != NULL) {
        PyRun_SimpleFileEx(fd, nslogPath.UTF8String, 1);
    }

    PyObject *siteModule = PyImport_ImportModule("site");
    if (siteModule == NULL) {
        if (error != NULL) {
            *error = [self currentPythonErrorWithCode:8 fallback:@"Could not import Python site module"];
        }
        return NO;
    }

    PyObject *addSiteDir = PyObject_GetAttrString(siteModule, "addsitedir");
    if (addSiteDir == NULL || !PyCallable_Check(addSiteDir)) {
        Py_XDECREF(addSiteDir);
        Py_DECREF(siteModule);
        if (error != NULL) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain code:9 userInfo:@{NSLocalizedDescriptionKey: @"Could not access site.addsitedir"}];
        }
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
        return NO;
    }

    PyEval_SaveThread();
    _initialized = YES;
    return YES;
}

- (nullable NSDictionary *)invokePythonMessage:(NSDictionary *)message error:(NSError **)error {
    NSData *messageData = [NSJSONSerialization dataWithJSONObject:message options:0 error:error];
    if (messageData == nil) {
        return nil;
    }
    NSString *messageJSON = [[NSString alloc] initWithData:messageData encoding:NSUTF8StringEncoding];

    PyObject *module = PyImport_ImportModule("obstacle_bridge_ios.ipserver_extension");
    if (module == NULL) {
        if (error != NULL) {
            *error = [self currentPythonErrorWithCode:11 fallback:@"Could not import obstacle_bridge_ios.ipserver_extension"];
        }
        return nil;
    }

    PyObject *callable = PyObject_GetAttrString(module, "handle_message_json");
    if (callable == NULL || !PyCallable_Check(callable)) {
        Py_XDECREF(callable);
        Py_DECREF(module);
        if (error != NULL) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain code:12 userInfo:@{NSLocalizedDescriptionKey: @"Python entrypoint handle_message_json is missing"}];
        }
        return nil;
    }

    PyObject *args = Py_BuildValue("(s)", messageJSON.UTF8String);
    PyObject *result = PyObject_CallObject(callable, args);
    Py_DECREF(args);
    Py_DECREF(callable);
    Py_DECREF(module);
    if (result == NULL) {
        if (error != NULL) {
            *error = [self currentPythonErrorWithCode:13 fallback:@"Python command execution failed"];
        }
        return nil;
    }

    const char *resultCString = PyUnicode_AsUTF8(result);
    NSString *resultJSON = resultCString == NULL ? @"{}" : [NSString stringWithUTF8String:resultCString];
    Py_DECREF(result);

    NSData *resultData = [resultJSON dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *payload = [NSJSONSerialization JSONObjectWithData:resultData options:0 error:error];
    if (![payload isKindOfClass:[NSDictionary class]]) {
        if (error != NULL && *error == nil) {
            *error = [NSError errorWithDomain:OBPythonBridgeErrorDomain code:14 userInfo:@{NSLocalizedDescriptionKey: @"Python response was not a JSON object"}];
        }
        return nil;
    }
    return payload;
}

- (NSError *)currentPythonErrorWithCode:(NSInteger)code fallback:(NSString *)fallback {
    if (!PyErr_Occurred()) {
        return [NSError errorWithDomain:OBPythonBridgeErrorDomain code:code userInfo:@{NSLocalizedDescriptionKey: fallback}];
    }

    PyObject *type = NULL;
    PyObject *value = NULL;
    PyObject *traceback = NULL;
    PyErr_Fetch(&type, &value, &traceback);
    PyErr_NormalizeException(&type, &value, &traceback);

    NSString *message = fallback;
    if (value != NULL) {
        PyObject *stringObject = PyObject_Str(value);
        if (stringObject != NULL) {
            const char *utf8 = PyUnicode_AsUTF8(stringObject);
            if (utf8 != NULL) {
                message = [NSString stringWithUTF8String:utf8];
            }
            Py_DECREF(stringObject);
        }
    }

    Py_XDECREF(type);
    Py_XDECREF(value);
    Py_XDECREF(traceback);

    return [NSError errorWithDomain:OBPythonBridgeErrorDomain code:code userInfo:@{NSLocalizedDescriptionKey: message}];
}

@end
