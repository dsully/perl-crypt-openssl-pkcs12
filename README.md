# NAME

Crypt::OpenSSL::PKCS12 - Perl extension to OpenSSL's PKCS12 API.

# SYNOPSIS

    use Crypt::OpenSSL::PKCS12;

    my $pass   = "your password";
    my $pkcs12 = Crypt::OpenSSL::PKCS12->new_from_file('cert.p12');

    print $pkcs12->certificate($pass);
    print $pkcs12->private_key($pass);

    if ($pkcs12->mac_ok($pass)) {
    ...

    # Creating a file
    $pkcs12->create('test-cert.pem', 'test-key.pem', $pass, 'out.p12', 'friendly name');


    # Creating a string
    my $pksc12_data = $pkcs12->create_as_string('test-cert.pem', 'test-key.pem', $pass, 'friendly name');

    # Reproducing OpenSSL's info
    my $info = $pkcs12->info($pass);

    # Accessing OpenSSL's info as a hash
    my $info_hash = $pkcs12->info_as_hash($pass);

# VERSION

This documentation describes version 1.94 of Crypt::OpenSSL::PKCS12

# DESCRIPTION

PKCS12 is a file format for storing cryptography objects as a single file or string. PKCS12 is commonly used to bundle a private key with its X.509 certificate or to bundle all the members of a chain of trust.

This distribution implements a subset of OpenSSL's PKCS12 API.

# SUBROUTINES/METHODS

- new( )
- legacy\_support ( )

    Check whether the openssl version installed supports the legacy provider.

- new\_from\_string( `$string` )
- new\_from\_file( `$filename` )

    Create a new Crypt::OpenSSL::PKCS12 instance.

- certificate( \[`$pass`\] )

    Get the Base64 representation of the certificate.

- ca\_certificate( \[`$pass`\] )

    Get the Base64 representation of the CA certificate chain.

- private\_key( \[`$pass`\] )

    Get the Base64 representation of the private key.

- as\_string( \[`$pass`\] )

    Get the binary represenation as a string.

- mac\_ok( \[`$pass`\] )

    Verifiy the certificates Message Authentication Code

- changepass( `$old`, `$new` )

    Change a certificate's password.

- create( `$cert`, `$key`, `$pass`, `$output_file`, `$friendly_name` )

    Create a new PKCS12 certificate. $cert & $key may either be strings or filenames.

    `$friendly_name` is optional.

- create\_as\_string( `$cert`, `$key`, `$pass`, `$friendly_name` )

    Create a new PKCS12 certificate string. $cert & $key may either be strings or filenames.

    `$friendly_name` is optional.

    Returns a string holding the PKCS12 certicate.

- info( `$pass` )

    Returns a string containing the output of information about the pkcs12 file in
    the same format as produced by the openssl command:

        openssl pkcs12 -in certs/test_le_1.1.p12 -info -nodes

- info\_as\_hash( `$pass` )

    Places the information about the pkcs12 file, the certificates and keys
    in a hash.

    The format of the hash is complex to represent the data in the PKCS12 file:

    Essentially, the hash follows the format of the -info output.

    1\. pkcs7\_data and pkcs7\_encrypted\_data are arrays as more than one of each can exist
    2\. mac provieds the top level mac parameters for the file
    3\. safe\_contents\_bag is an array that contains an array of bags
    4\. bags is an array of bags
    5\. a bag is a container for a key or certificate

    Each bag has a type and the following are available:

    1\. key\_bag
    2\. certificate\_bag
    3\. shrouded\_keybag
    4\. secret\_bag
    5\. safe\_contents\_bag

    {
        mac                    {
            digest        "sha1",
            iteration     2048,
            length        20,
            salt\_length   20
        },
        pkcs7\_data             \[
            \[0\] {
                    bags   \[
                        \[0\] {
                                bag\_attributes   {
                                    friendlyName   "...",
                                    localKeyID     "..." (dualvar: 54)
                                },
                                key              "...",
                                key\_attributes   {
                                    "X509v3 Key Usage"   10
                                },
                                parameters       {
                                    iteration        10000,
                                    nid\_long\_name    "PBKDF2",
                                    nid\_short\_name   "PBKDF2"
                                },
                                type             "shrouded\_keybag"
                            }
                    \]
                },
            \[1\] {
                    safe\_contents\_bag   \[
                        \[0\] {
                                bags   \[
                                    \[0\] {
                                            bag\_attributes   {
                                                localKeyID   "01" (dualvar: 1)
                                                friendlyName   "",
                                            },
                                            cert             "...".
                                            issuer           "...",
                                            subject          "...",
                                            type             "certificate\_bag"
                                            }
                                \],
                                type   "safe\_contents\_bag"
                            }
                    \]
                },
            \[2\] {
                    bags   \[
                        \[0\] {
                                bag\_attributes   {
                                    localKeyID   "02" (dualvar: 2)
                                },
                                cert             "...",
                                issuer           "...",
                                subject          "...",
                                type             "certificate\_bag"
                            }
                    \]
                },
        \],
        pkcs7\_encrypted\_data   \[
            \[0\] {
                    bags         \[
                        \[0\] {
                                bag\_attributes   {
                                    2.16.840.1.113894.746875.1.1   "<Unsupported tag 6>",
                                    friendlyName                   "..."
                                },
                                cert             "...",
                                issuer           "...",
                                subject          "...",
                                type             "certificate\_bag"
                            },
                        \[1\] {
                                bag\_attributes   {
                                    friendlyName   "...",
                                    localKeyID     "..." (dualvar: 54)
                                },
                                cert             "...",
                                issuer           "...",
                                subject          "...",
                                type             "certificate\_bag"
                            }
                    \],
                    parameters   {
                        iteration        10000,
                        nid\_long\_name    "PBKDF2",
                        nid\_short\_name   "PBKDF2"
                    }
                }
        \]
    }

# EXPORTS

None by default.

On request:

- `NOKEYS`
- `NOCERTS`
- `INFO`
- `CLCERTS`
- `CACERTS`

# DIAGNOSTICS

No diagnostics are documented at this time

# CONFIGURATION AND ENVIRONMENT

No special environment or configuration is required.

# DEPENDENCIES

This distribution has the following dependencies

- An installation of OpenSSL, either version 1.X.X or version 3.X.X
- Perl 5.8

# SEE ALSO

- OpenSSL(1) ([HTTP version with OpenSSL.org](https://www.openssl.org/docs/man1.1.1/man1/openssl.html))
- [Crypt::OpenSSL::X509](https://metacpan.org/pod/Crypt::OpenSSL::X509)
- [Crypt::OpenSSL::RSA](https://metacpan.org/pod/Crypt::OpenSSL::RSA)
- [Crypt::OpenSSL::Bignum](https://metacpan.org/pod/Crypt::OpenSSL::Bignum)
- [OpenSSL.org](https://www.openssl.org/)
- [Wikipedia: PKCS12](https://en.wikipedia.org/wiki/PKCS_12)
- [RFC:7292: "PKCS #12: Personal Information Exchange Syntax v1.1"](https://datatracker.ietf.org/doc/html/rfc7292)

# INCOMPATIBILITIES

Currently the library has been updated to support both OpenSSL 1.X.X and OpenSSL 3.X.X

# BUGS AND LIMITATIONS

Please see the [GitHub repository](https://github.com/dsully/perl-crypt-openssl-pkcs12/issues) for known issues.

# AUTHOR

- Dan Sully, <daniel@cpan.org>

Current maintainer

- jonasbn

# CONTRIBUTORS

In alphabetical order, contributors, bug reporters and all

- @mmuehlenhoff
- @sectokia
- @SmartCodeMaker
- Alexandr Ciornii, @chorny
- Christopher Hoskin, @mans0954
- Daisuke Murase, @typester
- Darko Prelec, @dprelec
- David Steinbrunner, @dsteinbrunner
- Gianni Ceccarelli, @dakkar
- Giuseppe Di Terlizzi, @giterlizzi
- H.Merijn Brand, @tux
- Hakim, @osfameron
- J. Nick Koston, @bdraco
- James Rouzier, @jrouzierinverse
- jonasbn. @jonasbn
- Kelson, @kelson42
- Lance Wicks, @lancew
- Leonid Antonenkov
- Masayuki Matsuki, @songmu
- Mikołaj Zalewski
- Shoichi Kaji
- Slaven Rezić
- Timothy Legge, @timlegge
- Todd Rinaldo, @toddr

# LICENSE AND COPYRIGHT

Copyright 2004-2024 by Dan Sully

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.
