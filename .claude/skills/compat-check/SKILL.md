---
name: compat-check
description: Remind Claude of OpenSSL/Perl version compatibility constraints before editing PKCS12.xs. Claude-only — not user-invocable.
user-invocable: false
---

Before editing PKCS12.xs, review these compatibility constraints:

**OpenSSL version guards**
- Code targeting OpenSSL < 1.1.0 must use the compat macros defined at the top of PKCS12.xs (e.g. `PKCS12_SAFEBAG_get0_p8inf`, `CONST_PKCS8_PRIV_KEY_INFO`, `CONST_STACK_OF`). Never call the raw OpenSSL 1.1+ symbol without the macro wrapper.
- OpenSSL 3.x provider code (`OSSL_PROVIDER`, `legacy`, `deflt` globals) must be wrapped in `#if OPENSSL_VERSION_NUMBER >= 0x30000000L`.
- The version boundary `0x10100000L` separates the pre-1.1 compat block from the 1.1+ definitions — new macros go in both branches.

**Perl version targets**
- The distribution targets Perl 5.8+. Avoid XS APIs introduced after 5.8 unless guarded by `#if PERL_VERSION >= X`.
- `ppport.h` (from Devel::PPPort) backfills many newer XS macros — check it covers any new macro before adding a manual compat guard.

**Platform differences**
- macOS (darwin): `LDDLFLAGS` is set differently in `Makefile.PL` — do not assume Linux `-rpath` patterns apply.
- Strawberry Perl (Windows): `OPENSSL_NO_SCRYPT` is defined; older versions link against `-leay32` instead of `-lcrypto`.
- Solaris/SunOS: uses `OPTIMIZE` rather than `LDDLFLAGS`.

**Test certificates**
- Tests select `certs/test_le_1.1.p12` for OpenSSL ≤ 1.1 and `certs/test.p12` for 3.x. If adding a new test that depends on OpenSSL version, follow this same conditional pattern using `openssl_version()` from `Crypt::OpenSSL::Guess`.
