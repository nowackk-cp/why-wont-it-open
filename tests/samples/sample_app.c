/* A real program built by the MSVC linker that imports fakedep.dll. It is
   never executed by the tests; it is only analysed. */
int fakedep_init(void);
int fakedep_run(void);
int main(void) { return fakedep_init() + fakedep_run(); }
