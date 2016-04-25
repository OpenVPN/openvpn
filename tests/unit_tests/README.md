Unit Tests
==========

This directory contains unit tests for openvpn.

Run tests
------------

Tests are run by `make check`. A failed tests stops test exeution. To run all
tests regardless of errors call `make -k check`.

Add new tests to existing test suite
--------------------

Test suites are organized in directories. [00_compile](00_compile) is an example
for a test suite with two test executables.

Add new test suites
--------------------

A new test suite needs a new subdirectory, e.g. `test_suite`, with a `Makefile.am`.

New test suites need to be registered
*  add the new directory to this folders `Makefile.am` `SUBDIRS`.
*  edit `configure.ac` and add the `Makefile` to `AC_CONFIG_FILES`.
*  run `./configure`

