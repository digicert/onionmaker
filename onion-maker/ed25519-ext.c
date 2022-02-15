#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "ed25519.h"


static PyObject* py_ed25519_sign(PyObject* module, PyObject* args) {
    PyObject* ret = NULL;

    char signature[64];

    Py_buffer message, public_key, private_key;

    if (!PyArg_ParseTuple(args, "s*|s*|s*", &public_key, &private_key, &message)) {
        goto error;
    }

    if (public_key.len != 32) {
        PyErr_Format(PyExc_ValueError, "Public key has invalid length");
        goto error;
    }

    if (private_key.len != 64) {
        PyErr_Format(PyExc_ValueError, "Private key has invalid length");
        goto error;
    }

    ed25519_sign(signature, message.buf, message.len, public_key.buf, private_key.buf);

    ret = Py_BuildValue("y#", signature, sizeof(signature));

    goto done;
error:
    ret = NULL;
done:
    return ret;
}


static PyMethodDef Ed25519Methods[] = {
    {"sign", py_ed25519_sign, METH_VARARGS, "Signs a message with the specified Ed25519 private key."},
    {NULL, NULL, 0, NULL}
};


static struct PyModuleDef ed25519module = {
    PyModuleDef_HEAD_INIT,
    "ed25519",
    NULL,
    -1,
    Ed25519Methods
};

PyMODINIT_FUNC PyInit_ed25519(void) {
    return PyModule_Create(&ed25519module);
}