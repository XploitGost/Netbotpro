#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <string.h>

typedef struct {
    PyObject *text_fn, *fallback, *sensitive, *empty_fields;
    PyObject *texts, *keys, *empty, *hidden, *hyphen, *underscore;
    int fast_ascii;
} WalkState;

static unsigned char ascii_lower(unsigned char value) {
    return value >= 'A' && value <= 'Z' ? value + ('a' - 'A') : value;
}

static int prefix(const unsigned char *text, Py_ssize_t length, const char *marker) {
    for (Py_ssize_t i = 0; marker[i]; i++) {
        if (i >= length || ascii_lower(text[i]) != (unsigned char)marker[i]) return 0;
    }
    return 1;
}

static int candidate(PyObject *text) {
    const unsigned char *data = PyUnicode_1BYTE_DATA(text);
    Py_ssize_t length = PyUnicode_GET_LENGTH(text);
    for (Py_ssize_t i = 0; i < length; i++) {
        const unsigned char *part = data + i;
        Py_ssize_t remaining = length - i;
        switch (ascii_lower(data[i])) {
            case 'a': if (prefix(part, remaining, "auth") || prefix(part, remaining, "api")) return 1; break;
            case 'b': if (prefix(part, remaining, "basic") || prefix(part, remaining, "bearer")) return 1; break;
            case 'c': if (prefix(part, remaining, "cookie") || prefix(part, remaining, "code")) return 1; break;
            case 'e': if (prefix(part, remaining, "eyj")) return 1; break;
            case 'j': if (prefix(part, remaining, "jwt")) return 1; break;
            case 'p': if (prefix(part, remaining, "pass") || prefix(part, remaining, "pwd")) return 1; break;
            case 's': if (prefix(part, remaining, "secret") || prefix(part, remaining, "session")) return 1; break;
            case 't': if (prefix(part, remaining, "token")) return 1; break;
        }
    }
    return 0;
}

static PyObject *walk(PyObject *value, WalkState *state);

static PyObject *python_walk(PyObject *value, WalkState *state) {
    return PyObject_CallFunctionObjArgs(state->fallback, value, state->texts,
                                       state->empty_fields, state->keys, NULL);
}

static int classify(PyObject *key, WalkState *state) {
    PyObject *cached = PyDict_GetItemWithError(state->keys, key);
    if (cached) return (int)PyLong_AsLong(cached);
    if (PyErr_Occurred()) return -1;
    int already_lower = PyUnicode_IS_ASCII(key);
    if (already_lower) {
        const unsigned char *data = PyUnicode_1BYTE_DATA(key);
        for (Py_ssize_t i = 0; i < PyUnicode_GET_LENGTH(key); i++) {
            if (data[i] >= 'A' && data[i] <= 'Z') { already_lower = 0; break; }
        }
    }
    PyObject *lower = already_lower ? Py_NewRef(key) : PyObject_CallMethod(key, "lower", NULL);
    if (!lower) return -1;
    int code = PySequence_Contains(state->empty_fields, lower);
    if (code < 0) { Py_DECREF(lower); return -1; }
    if (code) code = 2;
    else {
        int normalized_ascii = PyUnicode_IS_ASCII(lower) &&
            memchr(PyUnicode_1BYTE_DATA(lower), '-', (size_t)PyUnicode_GET_LENGTH(lower)) == NULL;
        PyObject *normalized = normalized_ascii ? Py_NewRef(lower) :
            PyUnicode_Replace(lower, state->hyphen, state->underscore, -1);
        if (!normalized) { Py_DECREF(lower); return -1; }
        code = PySequence_Contains(state->sensitive, normalized);
        Py_DECREF(normalized);
    }
    Py_DECREF(lower);
    if (code < 0) return -1;
    if (PyDict_Size(state->keys) < 128) {
        PyObject *number = PyLong_FromLong(code);
        if (!number) return -1;
        int status = PyDict_SetItem(state->keys, key, number);
        Py_DECREF(number);
        if (status < 0) return -1;
    }
    return code;
}

static PyObject *walk_dict(PyObject *value, WalkState *state) {
    PyObject *items = PyDict_Items(value);
    if (!items) return NULL;
    Py_ssize_t length = PyList_GET_SIZE(items);
    for (Py_ssize_t i = 0; i < length; i++) {
        if (!PyUnicode_CheckExact(PyTuple_GET_ITEM(PyList_GET_ITEM(items, i), 0))) {
            Py_DECREF(items);
            return python_walk(value, state);
        }
    }
    PyObject *result = PyDict_New();
    if (!result) { Py_DECREF(items); return NULL; }
    for (Py_ssize_t i = 0; i < length; i++) {
        PyObject *pair = PyList_GET_ITEM(items, i);
        PyObject *key = PyTuple_GET_ITEM(pair, 0);
        int code = classify(key, state);
        if (code < 0) goto failed;
        PyObject *item = code == 2 ? Py_NewRef(state->empty) :
                         code == 1 ? Py_NewRef(state->hidden) :
                         walk(PyTuple_GET_ITEM(pair, 1), state);
        if (!item) goto failed;
        int status = PyDict_SetItem(result, key, item);
        Py_DECREF(item);
        if (status < 0) goto failed;
    }
    Py_DECREF(items);
    return result;
failed:
    Py_DECREF(items);
    Py_DECREF(result);
    return NULL;
}

static PyObject *walk_sequence(PyObject *value, WalkState *state) {
    PyObject *snapshot = PySequence_List(value);
    if (!snapshot) return NULL;
    Py_ssize_t length = PyList_GET_SIZE(snapshot);
    PyObject *result = PyList_New(length);
    if (!result) { Py_DECREF(snapshot); return NULL; }
    for (Py_ssize_t i = 0; i < length; i++) {
        PyObject *item = walk(PyList_GET_ITEM(snapshot, i), state);
        if (!item) { Py_DECREF(snapshot); Py_DECREF(result); return NULL; }
        PyList_SET_ITEM(result, i, item);
    }
    Py_DECREF(snapshot);
    return result;
}

static PyObject *walk(PyObject *value, WalkState *state) {
    if (Py_EnterRecursiveCall(" while redacting metadata")) return NULL;
    PyObject *result = NULL;
    if (PyUnicode_CheckExact(value)) {
        PyObject *cached = PyDict_GetItemWithError(state->texts, value);
        if (cached) result = Py_NewRef(cached);
        else if (!PyErr_Occurred()) {
            result = state->fast_ascii && PyUnicode_IS_ASCII(value) && !candidate(value)
                     ? Py_NewRef(value) : PyObject_CallOneArg(state->text_fn, value);
            if (result && PyDict_Size(state->texts) < 256 &&
                PyDict_SetItem(state->texts, value, result) < 0) Py_CLEAR(result);
        }
    } else if (PyDict_CheckExact(value)) result = walk_dict(value, state);
    else if (PyList_CheckExact(value) || PyTuple_CheckExact(value)) result = walk_sequence(value, state);
    else if (PyUnicode_Check(value) || PyDict_Check(value) || PyList_Check(value) || PyTuple_Check(value))
        result = python_walk(value, state);
    else result = Py_NewRef(value);
    Py_LeaveRecursiveCall();
    return result;
}

static PyObject *redact(PyObject *self, PyObject *args) {
    PyObject *value;
    PyObject *pattern = Py_None;
    WalkState state = {0};
    if (!PyArg_ParseTuple(args, "OOOOO|O:redact", &value, &state.text_fn,
                          &state.fallback, &state.sensitive, &state.empty_fields, &pattern)) return NULL;
    /* Disable this shortcut if Python's candidate rule is ever changed. */
    state.fast_ascii = PyUnicode_CheckExact(pattern) &&
        PyUnicode_CompareWithASCIIString(pattern, "auth|cookie|basic|bearer|token|api|code|pass|pwd|secret|session|jwt|eyj") == 0;
    state.texts = PyDict_New();
    state.keys = PyDict_New();
    state.empty = PyUnicode_FromString("");
    state.hidden = PyUnicode_FromString("[REDACTED]");
    state.hyphen = PyUnicode_FromString("-");
    state.underscore = PyUnicode_FromString("_");
    PyObject *result = NULL;
    if (state.texts && state.keys && state.empty && state.hidden && state.hyphen && state.underscore)
        result = walk(value, &state);
    Py_XDECREF(state.texts);
    Py_XDECREF(state.keys);
    Py_XDECREF(state.empty);
    Py_XDECREF(state.hidden);
    Py_XDECREF(state.hyphen);
    Py_XDECREF(state.underscore);
    return result;
}

static PyMethodDef methods[] = {
    {"redact", redact, METH_VARARGS, "Detached redaction using the Python text rules."},
    {NULL, NULL, 0, NULL}
};
static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "_privacy_walk", NULL, -1, methods};
PyMODINIT_FUNC PyInit__privacy_walk(void) { return PyModule_Create(&module); }
