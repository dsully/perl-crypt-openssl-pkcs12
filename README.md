# NAME

Crypt::OpenSSL::PKCS12 - Perl extension to OpenSSL's PKCS12 API.

# SYNOPSIS

    use Crypt::OpenSSL::PKCS12;

    my $pass   = "your password";
    my $pkcs12 = Crypt::OpenSSL::PKCS12->new_from_file('cert.p12');

    print $pkcs12->certificate($pass);
    print $pkcs12->private_key($pass);

    if ($pkcs12->mac_ok($pass)) {
      # MAC verification passed
    }

    # Creating a file
    $pkcs12->create('test-cert.pem', 'test-key.pem', $pass, 'out.p12', 'friendly name');


    # Creating a string
    my $pkcs12_data = $pkcs12->create_as_string('test-cert.pem', 'test-key.pem', $pass, 'friendly name');

    # Reproducing OpenSSL's info
    my $info = $pkcs12->info($pass);

    # Accessing OpenSSL's info as a hash
    my $info_hash = $pkcs12->info_as_hash($pass);

# VERSION

This documentation describes version 1.97 of Crypt::OpenSSL::PKCS12

# DESCRIPTION

PKCS12 is a file format for storing cryptography objects as a single file or string. PKCS12 is commonly used to bundle a private key with its X.509 certificate or to bundle all the members of a chain of trust.

This distribution implements a subset of OpenSSL's PKCS12 API.

# SUBROUTINES/METHODS

- new( )

    Create an empty Crypt::OpenSSL::PKCS12 object. Use `new_from_string()` or
    `new_from_file()` to load an existing PKCS12 structure.

- legacy\_support ( )

    Returns true if the legacy provider has been successfully loaded by a prior
    constructor call (`new_from_string()` or `new_from_file()`). Always returns
    true on OpenSSL 1.x (where the legacy provider concept does not apply). On
    OpenSSL 3.x, returns true only if the legacy provider was loaded during the
    most recent constructor call; calling `legacy_support()` before constructing
    an object may return false even if the provider is loadable.

- new\_from\_string( `$string` )
- new\_from\_file( `$filename` )

    Create a new Crypt::OpenSSL::PKCS12 instance from a binary PKCS12 string or
    from a file path respectively. Both forms croak on error (invalid format,
    unreadable file, OpenSSL parse failure). The binary string passed to
    `new_from_string()` must not carry Perl's UTF-8 flag; use
    `Encode::encode('octets', $str)` if needed.

- certificate( \[`$pass`\] )

    Returns the end-entity certificate as a PEM-encoded string (Base64 with
    `-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----` headers).
    `$pass` is required when the PKCS12 file is password-protected. Returns an
    empty string if the password is wrong or no client certificate is present.

- ca\_certificate( \[`$pass`\] )

    Returns any CA certificates in the chain as a concatenated PEM string.
    Returns an empty string if no CA certificates are present. `$pass` is
    required when the PKCS12 file is password-protected.

- private\_key( \[`$pass`\] )

    Returns the private key as a PEM-encoded string. `$pass` is required when
    the PKCS12 file is password-protected. Returns an empty string if no private
    key is present or if decryption fails (wrong password).

- as\_string( )

    Returns the PKCS12 structure as a raw binary DER string. Useful for writing
    to a file or transmitting over a network without touching the filesystem.
    The in-memory structure is serialized as-is; no password is needed or accepted.

- mac\_ok( \[`$pass`\] )

    Verifies the Message Authentication Code (MAC) of the PKCS12 structure using
    `$pass`. Returns true if the MAC is valid. Croaks on failure (wrong
    password, corrupted file, or OpenSSL error).

- changepass( `$old`, `$new` )

    Re-encrypts the PKCS12 structure with a new password. `$old` is the current
    password; `$new` is the replacement. Returns false on failure.

    **Note:** Changing the PKCS12 password is not reliably supported on OpenSSL
    3.x; `changepass()` may return false or fail silently. Consider
    re-creating the PKCS12 structure with `create()` instead.

- create( `$cert`, `$key`, `$pass`, `$output_file`, `$friendly_name` )

    Creates a new PKCS12 file at `$output_file`. `$cert` and `$key` may each be
    either a PEM string (detected by a `"-----"` prefix) or a filesystem path.
    `$pass` is used to encrypt the private key. `$friendly_name` is optional and
    sets the `friendlyName` bag attribute. Croaks on any OpenSSL error.

- create\_as\_string( `$cert`, `$key`, `$pass`, `$friendly_name` )

    Same as `create()` but returns the PKCS12 structure as a raw binary DER string
    instead of writing to a file. `$cert` and `$key` may each be a PEM string or
    a filesystem path. `$friendly_name` is optional. Croaks on any OpenSSL error.

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
                                    localKeyID     "54"
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
                                                localKeyID   "01"
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
                                    localKeyID   "02"
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
                                    localKeyID     "54"
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

    Attributes such as `localKeyID` are stored as plain hex strings (e.g.
    `"54"`, `"01"`). Always treat these values as strings in code.

# EXPORTS

None by default.

On request:

- `NOKEYS`

    Flag: suppress output of private keys.

- `NOCERTS`

    Flag: suppress output of certificates.

- `INFO`

    Flag: enable structural info output (used internally by `info()` and
    `info_as_hash()`; output is returned as a string or hash, not printed).

- `CLCERTS`

    Flag: output only client (end-entity) certificates.

- `CACERTS`

    Flag: output only CA certificates.

These flags mirror the corresponding `-nokeys`, `-nocerts`, `-info`,
`-clcerts`, and `-cacerts` options of the `openssl pkcs12` command.

# DIAGNOSTICS

- **"OpenSSL error: ..."** — an OpenSSL call failed. The trailing
message is taken from `ERR_reason_error_string()` and identifies the
specific failure (e.g. `"bad decrypt"` for a wrong password).
- **"Error opening ..."** — `create()` could not open the specified
output file path for writing.

# CONFIGURATION AND ENVIRONMENT

No special environment or configuration is required.

# DEPENDENCIES

This distribution has the following dependencies

- An installation of OpenSSL, either version 1.X.X or version 3.X.X
- Perl 5.14

# SEE ALSO

- OpenSSL(1) ([HTTP version with OpenSSL.org](https://www.openssl.org/docs/manmaster/man1/openssl.html))
- [Crypt::OpenSSL::X509](https://metacpan.org/pod/Crypt::OpenSSL::X509)
- [Crypt::OpenSSL::RSA](https://metacpan.org/pod/Crypt::OpenSSL::RSA)
- [Crypt::OpenSSL::Bignum](https://metacpan.org/pod/Crypt::OpenSSL::Bignum)
- [OpenSSL.org](https://www.openssl.org/)
- [Wikipedia: OpenSSL](https://en.wikipedia.org/wiki/OpenSSL)
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

Copyright 2004 by Dan Sully

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.
