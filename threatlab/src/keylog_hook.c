/* Dummy shared library — triggers ld cache "keylog" detection */
void __attribute__((constructor)) init(void) { }
