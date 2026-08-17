# Checklist for Contributions

## Introduction

This documents all policies applied to any change that should be applied
in this repository. It is separated in two parts. The first part describes
the checklist that any submitter should apply. The second part describes
the checklist that integrators need to apply before actually merging the
change.

In general the Integrator Checklist does imply that all checks from the
Submitter Checklist have been passed. They are not repeated.

## Submitter Checklist

### Commit message

* Does the commit message accurately describe the change?
* Does it end with the line `Signed-off-by: My Name <my@email.com>` ?

### Automated tests

* Did the change pass a local `make` build?
* Did the change pass a local run of `make check`?
* Have you verified the code formatting with clang-format?
* Is the code covered by Unit Tests? If not, have you considered adding
  a new Unit Test?

### Change-specific checks

* Does your change require adaptions on both server and client side
  because it changes the wire-protocol?
  * Did you propose a change to http://github.com/openvpn-rfc/
    to agree on the protocol format changes?
* Does your change add, remove, or change a config option?
  * Have you adapted the usage text (`openvpn --help`)?
  * Have you adapted the man page text (`man -l ./doc/openvpn.8`)?
* Have you reviewed all code comments around code you touched to
  check whether they need to be adapted?
* If your change adds new files, are they added in some Makefile.am
  statement that will make sure they up in the distributed source
  tarballs?

## Integrator Checklist

### General

* Is the exact code change to be merged available as an email on openvpn-devel
  mailing list (note: this does not apply to the commit message since that needs
  to be massaged anyway)?
* If not, is the change to merge a trivial cherry-pick?

### Commit message

* Does it contain the pointer to the email on openvpn-devel?
  This means a line `Message-Id: <actual msg id>` and a line
  `URL: <url to mail-archive.com copy of the mail>`. If mail-archive.com
  is not working, alternatively an URL to SourceForge's mail archive
  is also acceptable.
* Does it contain at least one `Acked-by` line from a known OpenVPN
  core developer? Valid sources for `Acked-by` lines are mails on
  the mailing list or +2 votes in Gerrit.
* If the change is a security fix, does it contain a `CVE:` line in
  the format `CVE: <Year>-<Number>`?
* If the change fixes a Github issue, does it contain a line
  `Github: OpenVPN/openvpn#<Number>`? (Other repositories might
  also be referenced if applicable)
* Have you considered adding a `Reported-by:` line? This is usual
  for attribution for security issues but might be added for any
  report where the reporter added significant value by their report.
* If doing a cherry-pick, have you made sure to use `git cherry-pick -x`
  to add a reference to the picked commit?

#### Gerrit specific

Additional checks if the change was reviewed and submitted via Gerrit.

* Does it contain a correct `Gerrit URL:` line? (This is generally ensured
  by using `gerrit-send-email.py`)
* Is the `Change-Id:` line present and located in the last paragraph of the
  message? (If not in the last paragraph, Gerrit will ignore it)

### Automated tests

* Has the change passed a full build run in buildbot? (Usually ensured via
  Gerrit). This ensures the following points (which otherwise might need to
  be considered separately):
  * Build passes on multiple platforms (Linux, FreeBSD, Windows, macOS, other BSDs)
  * Build passes with multiple compilers (GCC, Clang, MSVC, GCC MinGW)
  * Build passes with multiple configurations (`--enable-small`, `--disable-management`,
    etc.)
  * Build passes with multiple versions of multiple SSL libraries (OpenSSL, mbedTLS)
  * Unit tests pass in all these settings
  * t\_server\_null, t\_client pass in all these settings
  * t\_server passes
  * Verified clang-format code formatting
* If buildbot ignored the change that usually means that it did not match the
  file match list (e.g. only changes in `.github/`). Consider whether that seems
  correct.
* Has the change passed a GHA run?
* Do any of the tests actually exercise the code? If not, has someone other than the
  submitter done any manual verification?

### Backports

* Is it clear to which branches the change should be applied?
  * If it is a security fix, it should be applied to all branches that are
    affected and that are not "unsupported"
    (cf. https://community.openvpn.net/Pages/Supported%20versions)
  * If it is a bugfix, it should be applied to all branches that are in
    "Full stable support". Depending on the severity it might also be
    applied to branches in "Old stable support".
* Have you checked for all branches whether a trivial cherry-pick is
  possible or whether a backport is required? If a backport is required
  have you communicated this to the submitter?
