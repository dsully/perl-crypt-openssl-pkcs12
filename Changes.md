# Revision history for Perl extension Crypt::OpenSSL::PKCS12.

# 1.94 2024-10-01

- Merge of PR: [#52](https://github.com/dsully/perl-crypt-openssl-pkcs12/pull/52) from @dakkar, first time contributor to the distribution, thanks for the contribution
  This PR introduces a new feature, which allows for the extraction a certificate chain from a PKCS12 file via a new method `ca- certificate`

# 1.93 2024-09-28

- Inclusion of PR: [#51](https://github.com/dsully/perl-crypt-openssl-pkcs12/pull/51) aimed at addressing the following issues observed with previous release: `1.92`, thanks to @timlegge for the contribution
  - [#48](https://github.com/dsully/perl-crypt-openssl-pkcs12/issues/48)
  - [#49](https://github.com/dsully/perl-crypt-openssl-pkcs12/issues/49)
  - [#40](https://github.com/dsully/perl-crypt-openssl-pkcs12/issues/50)

# 1.92 2024-09-08

Addition of new feature supporting the OpenSSL info option, all via PR [#44](https://github.com/dsully/perl-crypt-openssl-pkcs12/pull/44) from @timlegge

## 1.91 Mon Jun 24 22:00:13 CEST 2024

Due to a mistake with the release numbering, the two trial releases, should not have been `1.10` and `1.11`, but `1.91` and `1.92` respectively. So there will be a jump from 1.9 to 1.91, since 1.9 is equivalent to 1.90.

This release contains changes tested on the two previous trial releases.

In addition the following changes have been adopted:

- PR: [#47](https://github.com/dsully/perl-crypt-openssl-pkcs12/pull/47) from @timlegge, improving support for building with OpenSSL located in non-standard locations

## 1.11 (TRIAL) Wed Jun  5 20:21:54 CEST 2024

- Improved support for older versions of OpenSSL via PR [#46](https://github.com/dsully/perl-crypt-openssl-pkcs12/pull/46) from @timlegge
  This should address reports on failing tests from CPAN testers, see also: [#45](https://github.com/dsully/perl-crypt-openssl-pkcs12/issues/45)

- Minor cleanup to repository files used for varies tools

## 1.10 (TRIAL) Fri Apr 26 16:09:56 CEST 2024

- Improved support for OpenSSL 3.0 via RT: [42](https://github.com/dsully/perl-crypt-openssl-pkcs12/pull/42) from @timlegge

- Distribution tooling changed from `Module::Install` to `Dist::Zilla`

## 1.9 Sat Nov 20 12:49:34 CET 2021

- Added new feature from `create_as_string` via PR #39 from James Rouzier (@jrouzierinverse), which returns the PKCS data as a string, for futher handling

- Bumped Perl requirement from Perl 5.6 to 5.8, due to use of UTF-8 in test suite

- POD cleaned up, more to come

## 1.8 Fri Nov 12 20:31:24 CET 2021

- Applied patch via PR #37 from @SmartCodeMaker, calculating of strings and handling Windows files properly

- Applied patch via PR #38 from @SmartCodeMaker, formatting print of SVs displays garbage as documented in the perlguts documentation

  REF: https://perldoc.perl.org/perlguts#Formatted-Printing-of-SVs

## 1.7  Fri May 21 21:16:53 CEST 2021

- Removed some unnecessary code from a test, the code would not compile on Perl 5.18

## 1.6  Thu May 20 07:32:35 CEST 2021

- Added encoding declaration to POD section, I had overlooked a special character in one of the names of the contributors

## 1.5  Wed May 19 22:03:48 CEST 2021

- Addressed minor issue with the implementation added in 1.4, fix lifted from Crypt::OpenSSL::X509 - Thanks Shoichi Kaji

- Added section on contributors to the POD

## 1.4  Sun Apr 11 16:23:54 CEST 2021

- Addressed issue with homebrew path reported for Crypt::OpenSSL::X509

  REF: https://github.com/dsully/perl-crypt-openssl-x509/issues/81

  The pattern is the same in this distribution

## 1.3  Thu Jun  4 21:39:30 CEST 2020

- Maintenance release addressing the broken inc/ configuration pointed out in: RT:77784 by HMBRAND

  REF: https://rt.cpan.org/Ticket/Display.html?id=77784

## 1.2  Sat Oct 27 09:37:04 CEST 2018

- Maintenance release addressing the missing exclusion of the MYMETA files issue spotted by Alexandr Ciornii (@chorny) #issue32

## 1.1  Fri Oct 26 07:54:48 CEST 2018

- PR from Todd Rinaldo (@toddr) Adding use of our instead of vars, since we are now bumping Perl version requirement
  from 5.005 to 5.6.0

- PR from Todd Rinaldo (@toddr) Exchange DynaLoader for XSLoader, bumping Perl version requirement
  from 5.005 to 5.6.0

- PR from Todd Rinaldo (@toddr) Add Makefile.PL support for perl 5.26.0 and above which don't include . in @INC

## 1.0  Mon Mar 19 21:20:49 CET 2018

- Re-release of 0.10, due to indexing issue with PAUSE/CPAN ref: #28

## 0.10  Wed Mar 14 08:11:54 CET 2018

- Patch from kelson (@kelson42) improving the code, going from two pass to one pass, speeding up the chain management PR #27

## 0.9   Sun Mar 11 19:45:18 CET 2018

- Patch from kelson (@kelson42) addressing compilation issues against OpenSSL 1.1.0 PR #24

## 0.8   Sun Nov 20 19:21:47 CET 2017

- Patch from jonasbn improving handling of C include paths

- Patch from jonasbn reinitializing inc/ and Module::Install integration

- Patch from Songmu adjusting use of paths and flags in Makefile.PL

- Patch from jonasbn adding inc/Module/Install/External.pm from Module::Install missing from MANIFEST

- Patch from jonasbn for compatibility with required C libraries installed via Homebrew on OSX

- Patch from jonasbn to address clang changes

- Patch from Christopher Hoskin enabling compatibility with OpenSSL 1.1.0 and backwards compatibility with OpenSSL 1.0.2

## 0.7   Fri Oct 24 06:16:43 PDT 2014

- Patch from Mikołaj Zalewski to fix C90 issue on CentOS.

- Patch from Darko Prelec to fix compile issue #2.

## 0.6   Thu May 10 10:44:30 PDT 2012

- Patch from Leonid Antonenkov to implement private key access.

- Misc compile fixes.

## 0.5   Sun May 18 08:19:14 PDT 2008

- Fix pod coverage tests.

## 0.4   Sat May 17 00:47:36 PDT 2008

- Stop cpansmoke from emailing me.

## 0.3   Fri Jan  5 15:36:28 PST 2007

- Add more POD & coverage.
- Fix META.yml

## 0.2   Thu Jan  4 10:21:31 PST 2007

- Use Module::Install

- Added tests.

- PKCS12 Create from JoNO

## 0.1   Thu Jan 29 17:01:38 PST 2004

- Initial release.
