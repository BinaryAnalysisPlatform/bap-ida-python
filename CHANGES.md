1.2.0
-----
* fixes IDA loader
* more robust comment parser

1.1.0
-----
* call BAP asynchronously (without blocking IDA)
* run several instances of BAP in parallel
* special attribute view (instead of `Alt-T` search)
* neater comment syntax (attr=value instead of sexp)
* task manager for primitive job control
* plugins are now callable from the menu (try `Ctrl-3`)
* each instance has its own view
* view selector can switch between views
* stderr and stdout are properly dumped into the view
* cross-platform implementation (Docker, Windows should work)
* more robust type emition
* new generic ida service integration (for calls to IDA from BAP)
* added unit tests
* Travis-CI integration
* code refactoring: more pythonic, PEP8 compilant, pylint-happy

0.1.0
-----
* initial release
