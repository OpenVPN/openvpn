Unit Tests
===========

This directory contains unit tests for openvpn. New features/bugfixes should be written in a test friendly way and come with corresponding tests.

Run tests
----------

Tests are run by `make check`. A failed tests stops test execution. To run all
tests regardless of errors call `make -k check`.

Add new tests to existing test suite
-------------------------------------

Test suites are organized in directories. [example_test/](example_test/) is an example
for a test suite with two test executables. Feel free to use it as a template for new tests.

Test suites
--------------------

Test suites live inside a subdirectory of `$ROOT/tests/unit_tests`, e.g. `$ROOT/tests/unit_tests/my_feature`.

Test suites are configured by a `Makefile.am`. Tests are executed by testdrivers. One testsuite can contain more than one testdriver.

### Hints
* Name suites & testdrivers in a way that the name of the driver says something about which component/feature is tested
* Name the testdriver executable `*_testdriver`. This way it gets picked up by the default `.gitignore`
  * If this is not feasible: Add all output to a `.gitignore`* Use descriptive test names: `coffee_brewing__with_no_beans__fails` vs. `test34`
* Testing a configurable feature?  Wrap test execution with a conditional (see [auth_pam](plugins/auth-pam/Makefile.am) for an example)
* Add multiple test-drivers when one testdriver looks crowded with tests

### New Test Suites
1.  Organize tests in folders for features.
2.  Add the new test directory to `SUBDIRS` in `Makefile.am`
3.  Edit `configure.ac` and add the new `Makefile` to `AC_CONFIG_FILES`
4.  Run `./configure`, and *enable* the feature you'd like to test
5.  Make sure that `make check` runs your tests
6.  Check: Would a stranger be able to easily find your tests by you looking at the test output?
7. Run `./configure`, and *disable* the feature you'd like to test
8.  Make sure that `make check` does *not run* your tests
