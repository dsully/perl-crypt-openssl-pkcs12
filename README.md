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
    my $pksc12_data = $pkcs12->create_as_string(
      catdir($base, 'test-cert.pem'),
      catdir($base, 'test-key.pem'),
      $pass,
      'Friendly Name'
    );

# DESCRIPTION

This implements a small bit of OpenSSL's PKCS12 API.

# FUNCTIONS

- new( )
- new\_from\_string( `$string` )
- new\_from\_file( `$filename` )

    Create a new Crypt::OpenSSL::PKCS12 instance.

- certificate( \[`$pass`\] )

    Get the Base64 representation of the certificate.

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

    $friendly\_name is optional.

- create\_as\_string( `$cert`, `$key`, `$pass`, `$friendly_name` )

    Create a new PKCS12 certificate string. $cert & $key may either be strings or filenames.

    $friendly\_name is optional.

# EXPORT

None by default.

On request:

- `NOKEYS`
- `NOCERTS`
- `INFO`
- `CLCERTS`
- `CACERTS`

# SEE ALSO

- OpenSSL(1)
- [Crypt::OpenSSL::X509](https://metacpan.org/pod/Crypt::OpenSSL::X509)
- [Crypt::OpenSSL::RSA](https://metacpan.org/pod/Crypt::OpenSSL::RSA)
- [Crypt::OpenSSL::Bignum](https://metacpan.org/pod/Crypt::OpenSSL::Bignum)

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
- Todd Rinaldo, @toddr

# COPYRIGHT AND LICENSE

Copyright 2004-2021 by Dan Sully

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.
