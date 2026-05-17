#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 11;
use File::Spec::Functions qw(:ALL);
use Crypt::OpenSSL::Guess;

BEGIN { use_ok('Crypt::OpenSSL::PKCS12') }

my ($major, $minor, $patch) = openssl_version();

my $base = 'certs';
my $pass = 'testing';

my $certfile;
if ($major le "1.1") {
    $certfile = catdir($base, 'test_le_1.1.p12');
} else {
    $certfile = catdir($base, 'test.p12');
}

my $pkcs12 = Crypt::OpenSSL::PKCS12->new_from_file($certfile);
ok($pkcs12, 'PKCS12 object created');

# Fix 1: mac_ok must return false for a wrong password, not croak.
# Previously it called PKCS12_verify_mac twice — the first call would croak
# on failure, making it impossible for mac_ok to ever return false.
{
    my $result = eval { $pkcs12->mac_ok('wrong-password') };
    is($@, '', 'mac_ok with wrong password does not croak');
    ok(!$result, 'mac_ok returns false for wrong password');
}

# mac_ok still returns true for the correct password
ok($pkcs12->mac_ok($pass), 'mac_ok returns true for correct password');

# Embedded NUL in password croaks for APIs that use strlen() internally.
# PKCS12_create() and PKCS12_newpass() cannot accept binary passwords.
{
    my $nul_pass = "pass\x00word";

    eval {
        $pkcs12->create(
            catdir($base, 'test-cert.pem'),
            catdir($base, 'test-key.pem'),
            $nul_pass,
            catdir($base, 'nul-out.p12'),
        );
    };
    like($@, qr/embedded NUL/i, 'create() croaks for NUL-containing password');
    unlink catdir($base, 'nul-out.p12');

    eval { $pkcs12->create_as_string(
        catdir($base, 'test-cert.pem'),
        catdir($base, 'test-key.pem'),
        $nul_pass,
    ) };
    like($@, qr/embedded NUL/i, 'create_as_string() croaks for NUL-containing password');

    SKIP: {
        if ($major =~ /^3\./) {
            skip("OpenSSL 3.x changepass not supported", 2);
        }
        eval { $pkcs12->changepass($nul_pass, 'newpass') };
        like($@, qr/embedded NUL/i, 'changepass() croaks for NUL-containing old password');

        eval { $pkcs12->changepass($pass, $nul_pass) };
        like($@, qr/embedded NUL/i, 'changepass() croaks for NUL-containing new password');
    }
}

# Regression guard for CVE-2026-8721 fix: SvPV (not SvPVbyte) must be used so
# that UTF-8 strings with codepoints > 255 reach OpenSSL without croaking.
# OpenSSL's PKCS12 code handles the UTF-8 -> UTF-16 BMPString conversion itself.
{
    my $wide_pass = "\x{65E5}\x{672C}\x{8A9E}"; # 日本語
    my $result = eval { $pkcs12->mac_ok($wide_pass) };
    is($@, '', 'mac_ok with wide-char (codepoint > 255) password does not croak');
    ok(!$result, 'mac_ok returns false (not croak) for wide-char password');
}
