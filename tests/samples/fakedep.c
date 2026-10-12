/* A tiny DLL; the .def file decides which functions are exported. */
int fakedep_init(void) { return 1; }
int fakedep_run(void) { return 2; }
