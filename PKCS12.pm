package Crypt::OpenSSL::PKCS12;

use warnings;
use strict;
use Exporter;

our $VERSION = '1.8';
our @ISA = qw(Exporter);

our @EXPORT_OK = qw(NOKEYS NOCERTS INFO CLCERTS CACERTS);

use XSLoader;

XSLoader::load 'Crypt::OpenSSL::PKCS12', $VERSION;

END {
  __PACKAGE__->__PKCS12_cleanup();
}

1;

__END__

=pod

=encoding UTF-8

=head1 NAME

Crypt::OpenSSL::PKCS12 - Perl extension to OpenSSL's PKCS12 API.

=head1 SYNOPSIS

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

=head1 DESCRIPTION

This implements a small bit of OpenSSL's PKCS12 API.

=head1 FUNCTIONS

=over 4

=item * new( )

=item * new_from_string( C<$string> )

=item * new_from_file( C<$filename> )

Create a new Crypt::OpenSSL::PKCS12 instance.

=item * certificate( [C<$pass>] )

Get the Base64 representation of the certificate.

=item * private_key( [C<$pass>] )

Get the Base64 representation of the private key.

=item * as_string( [C<$pass>] )

Get the binary represenation as a string.

=item * mac_ok( [C<$pass>] )

Verifiy the certificates Message Authentication Code

=item * changepass( C<$old>, C<$new> )

Change a certificate's password.

=item * create( C<$cert>, C<$key>, C<$pass>, C<$output_file>, C<$friendly_name> )

Create a new PKCS12 certificate. $cert & $key may either be strings or filenames.

C<$friendly_name> is optional.

=item * create_as_string( C<$cert>, C<$key>, C<$pass>, C<$friendly_name> )

Create a new PKCS12 certificate string. $cert & $key may either be strings or filenames.

C<$friendly_name> is optional.

Returns a string holding the PKCS12 certicate.

=back

=head1 EXPORT

None by default.

On request:

=over 4

=item * C<NOKEYS>

=item * C<NOCERTS>

=item * C<INFO>

=item * C<CLCERTS>

=item * C<CACERTS>

=back

=head1 SEE ALSO

=over

=item * OpenSSL(1)

=item * L<Crypt::OpenSSL::X509|https://metacpan.org/pod/Crypt::OpenSSL::X509>

=item * L<Crypt::OpenSSL::RSA|https://metacpan.org/pod/Crypt::OpenSSL::RSA>

=item * L<Crypt::OpenSSL::Bignum|https://metacpan.org/pod/Crypt::OpenSSL::Bignum>

=back

=head1 AUTHOR

=over

=item * Dan Sully, E<lt>daniel@cpan.orgE<gt>

=back

Current maintainer

=over

=item * jonasbn

=back

=head1 CONTRIBUTORS

In alphabetical order, contributors, bug reporters and all

=over

=item * @mmuehlenhoff

=item * @sectokia

=item * @SmartCodeMaker

=item * Alexandr Ciornii, @chorny

=item * Christopher Hoskin, @mans0954

=item * Daisuke Murase, @typester

=item * Darko Prelec, @dprelec

=item * David Steinbrunner, @dsteinbrunner

=item * Giuseppe Di Terlizzi, @giterlizzi

=item * H.Merijn Brand, @tux

=item * Hakim, @osfameron

=item * J. Nick Koston, @bdraco

=item * James Rouzier, @jrouzierinverse

=item * jonasbn. @jonasbn

=item * Kelson, @kelson42

=item * Lance Wicks, @lancew

=item * Leonid Antonenkov

=item * Masayuki Matsuki, @songmu

=item * Mikołaj Zalewski

=item * Shoichi Kaji

=item * Slaven Rezić

=item * Todd Rinaldo, @toddr

=back

=head1 COPYRIGHT AND LICENSE

Copyright 2004-2021 by Dan Sully

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut
