#import "ObstacleBridgePythonRuntime.h"

#include <Python/Python.h>

static BOOL OBPythonInitialized = NO;
static PyThreadState *OBPythonMainThreadState = NULL;

@implementation ObstacleBridgePythonRuntime

- (BOOL)startWithProviderConfigurationJSON:(NSString *)providerConfigurationJSON
                          parentBundlePath:(NSString *)parentBundlePath
                                     error:(NSError **)error {
    if (![self ensurePythonWithParentBundlePath:parentBundlePath error:error]) {
        return NO;
    }
    NSString *result = [self callModuleFunction:@"start"
                                      arguments:@[providerConfigurationJSON ?: @"{}", parentBundlePath ?: @""]
                                          error:error];
    if (result == nil) {
        return NO;
    }
    NSLog(@"ObstacleBridge extension Python runtime start result: %@", result);
    return ![result containsString:@"\"started\": false"];
}

- (void)stop {
    NSError *error = nil;
    NSString *result = [self callModuleFunction:@"stop" arguments:@[] error:&error];
    if (result == nil) {
        NSLog(@"ObstacleBridge extension Python runtime stop failed: %@", error.localizedDescription);
    } else {
        NSLog(@"ObstacleBridge extension Python runtime stop result: %@", result);
    }
}

- (NSString *)statusJSON {
    NSError *error = nil;
    NSString *result = [self callModuleFunction:@"status" arguments:@[] error:&error];
    if (result == nil) {
        return [NSString stringWithFormat:@"{\"started\":false,\"source\":\"packet-tunnel-extension-python\",\"error\":\"%@\"}",
                [self jsonEscapedString:error.localizedDescription ?: @"status failed"]];
    }
    return result;
}

- (BOOL)ensurePythonWithParentBundlePath:(NSString *)parentBundlePath error:(NSError **)error {
    @synchronized ([ObstacleBridgePythonRuntime class]) {
        if (OBPythonInitialized) {
            return YES;
        }

        NSString *pythonHome = [parentBundlePath stringByAppendingPathComponent:@"python"];
        NSString *stdlibPath = [pythonHome stringByAppendingPathComponent:@"lib/python3.14"];
        NSString *dynloadPath = [stdlibPath stringByAppendingPathComponent:@"lib-dynload"];
        NSString *appPath = [parentBundlePath stringByAppendingPathComponent:@"app"];
        NSString *appPackagesPath = [parentBundlePath stringByAppendingPathComponent:@"app_packages"];

        PyStatus status;
        PyPreConfig preconfig;
        PyConfig config;
        PyPreConfig_InitIsolatedConfig(&preconfig);
        PyConfig_InitIsolatedConfig(&config);
        preconfig.utf8_mode = 1;
        preconfig.configure_locale = 1;
        config.buffered_stdio = 0;
        config.write_bytecode = 0;
        config.module_search_paths_set = 1;

        status = Py_PreInitialize(&preconfig);
        if (PyStatus_Exception(status)) {
            [self fillError:error message:@"Unable to pre-initialize Python" detail:[NSString stringWithUTF8String:status.err_msg ?: "unknown"]];
            PyConfig_Clear(&config);
            return NO;
        }

        if (![self appendPythonPath:pythonHome toConfig:&config error:error setter:&config.home]) {
            PyConfig_Clear(&config);
            return NO;
        }
        if (![self appendSearchPath:stdlibPath toConfig:&config error:error]) {
            PyConfig_Clear(&config);
            return NO;
        }
        if (![self appendSearchPath:dynloadPath toConfig:&config error:error]) {
            PyConfig_Clear(&config);
            return NO;
        }
        if (![self appendSearchPath:appPath toConfig:&config error:error]) {
            PyConfig_Clear(&config);
            return NO;
        }

        status = Py_InitializeFromConfig(&config);
        PyConfig_Clear(&config);
        if (PyStatus_Exception(status)) {
            [self fillError:error message:@"Unable to initialize Python" detail:[NSString stringWithUTF8String:status.err_msg ?: "unknown"]];
            return NO;
        }

        PyObject *site = PyImport_ImportModule("site");
        PyObject *addsitedir = site ? PyObject_GetAttrString(site, "addsitedir") : NULL;
        PyObject *siteArg = PyUnicode_FromString([appPackagesPath UTF8String]);
        PyObject *siteArgs = siteArg ? PyTuple_Pack(1, siteArg) : NULL;
        PyObject *siteResult = (addsitedir && siteArgs) ? PyObject_CallObject(addsitedir, siteArgs) : NULL;
        Py_XDECREF(siteResult);
        Py_XDECREF(siteArgs);
        Py_XDECREF(siteArg);
        Py_XDECREF(addsitedir);
        Py_XDECREF(site);
        if (PyErr_Occurred()) {
            NSString *traceback = [self currentPythonException];
            [self fillError:error message:@"Unable to add app_packages to Python path" detail:traceback];
            return NO;
        }

        OBPythonInitialized = YES;
        OBPythonMainThreadState = PyEval_SaveThread();
        NSLog(@"ObstacleBridge extension Python initialized with parent bundle %@", parentBundlePath);
        return YES;
    }
}

- (BOOL)appendPythonPath:(NSString *)value
               toConfig:(PyConfig *)config
                  error:(NSError **)error
                 setter:(wchar_t **)setter {
    wchar_t *decoded = Py_DecodeLocale([value UTF8String], NULL);
    PyStatus status = PyConfig_SetString(config, setter, decoded);
    PyMem_RawFree(decoded);
    if (PyStatus_Exception(status)) {
        [self fillError:error message:@"Unable to configure Python path" detail:[NSString stringWithUTF8String:status.err_msg ?: "unknown"]];
        return NO;
    }
    return YES;
}

- (BOOL)appendSearchPath:(NSString *)value toConfig:(PyConfig *)config error:(NSError **)error {
    wchar_t *decoded = Py_DecodeLocale([value UTF8String], NULL);
    PyStatus status = PyWideStringList_Append(&config->module_search_paths, decoded);
    PyMem_RawFree(decoded);
    if (PyStatus_Exception(status)) {
        [self fillError:error message:@"Unable to append Python search path" detail:[NSString stringWithUTF8String:status.err_msg ?: "unknown"]];
        return NO;
    }
    return YES;
}

- (NSString *)callModuleFunction:(NSString *)functionName arguments:(NSArray<NSString *> *)arguments error:(NSError **)error {
    if (!OBPythonInitialized) {
        [self fillError:error message:@"Python is not initialized" detail:@""];
        return nil;
    }

    PyGILState_STATE gil = PyGILState_Ensure();
    NSString *resultString = nil;
    PyObject *module = PyImport_ImportModule("obstacle_bridge_ios.extension_runtime");
    PyObject *function = module ? PyObject_GetAttrString(module, [functionName UTF8String]) : NULL;
    PyObject *args = PyTuple_New(arguments.count);
    for (NSUInteger idx = 0; idx < arguments.count; idx++) {
        PyObject *value = PyUnicode_FromString([arguments[idx] UTF8String]);
        PyTuple_SetItem(args, idx, value);
    }
    PyObject *result = (function && PyCallable_Check(function)) ? PyObject_CallObject(function, args) : NULL;
    if (result != NULL) {
        PyObject *utf8 = PyUnicode_AsUTF8String(result);
        if (utf8 != NULL) {
            resultString = [NSString stringWithUTF8String:PyBytes_AsString(utf8)];
        }
        Py_XDECREF(utf8);
    } else {
        NSString *traceback = [self currentPythonException];
        [self fillError:error message:[NSString stringWithFormat:@"Python call %@ failed", functionName] detail:traceback];
    }
    Py_XDECREF(result);
    Py_XDECREF(args);
    Py_XDECREF(function);
    Py_XDECREF(module);
    PyGILState_Release(gil);
    return resultString;
}

- (NSString *)currentPythonException {
    if (!PyErr_Occurred()) {
        return @"";
    }
    PyObject *type = NULL;
    PyObject *value = NULL;
    PyObject *traceback = NULL;
    PyErr_Fetch(&type, &value, &traceback);
    PyErr_NormalizeException(&type, &value, &traceback);

    PyObject *tracebackModule = PyImport_ImportModule("traceback");
    PyObject *formatException = tracebackModule ? PyObject_GetAttrString(tracebackModule, "format_exception") : NULL;
    PyObject *list = (formatException && type && value) ? PyObject_CallFunctionObjArgs(formatException, type, value, traceback ?: Py_None, NULL) : NULL;
    PyObject *separator = PyUnicode_FromString("");
    PyObject *joined = (separator && list) ? PyUnicode_Join(separator, list) : NULL;
    NSString *result = joined ? [NSString stringWithUTF8String:PyUnicode_AsUTF8(joined)] : @"unknown Python exception";

    Py_XDECREF(joined);
    Py_XDECREF(separator);
    Py_XDECREF(list);
    Py_XDECREF(formatException);
    Py_XDECREF(tracebackModule);
    Py_XDECREF(type);
    Py_XDECREF(value);
    Py_XDECREF(traceback);
    return result ?: @"unknown Python exception";
}

- (void)fillError:(NSError **)error message:(NSString *)message detail:(NSString *)detail {
    if (error == NULL) {
        return;
    }
    NSString *full = detail.length ? [NSString stringWithFormat:@"%@: %@", message, detail] : message;
    *error = [NSError errorWithDomain:@"ObstacleBridgePythonRuntime"
                                 code:1
                             userInfo:@{NSLocalizedDescriptionKey: full}];
}

- (NSString *)jsonEscapedString:(NSString *)value {
    NSMutableString *escaped = [NSMutableString stringWithString:value ?: @""];
    [escaped replaceOccurrencesOfString:@"\\" withString:@"\\\\" options:0 range:NSMakeRange(0, escaped.length)];
    [escaped replaceOccurrencesOfString:@"\"" withString:@"\\\"" options:0 range:NSMakeRange(0, escaped.length)];
    [escaped replaceOccurrencesOfString:@"\n" withString:@"\\n" options:0 range:NSMakeRange(0, escaped.length)];
    return escaped;
}

@end
