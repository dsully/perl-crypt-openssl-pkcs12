package Crypt::OpenSSL::PKCS12;

use strict;
use vars qw($VERSION @EXPORT_OK);
use Exporter;
use base qw(Exporter);

$VERSION = '0.2';

@EXPORT_OK = qw(NOKEYS NOCERTS INFO CLCERTS CACERTS);

BOOT_XS: {
	require DynaLoader;

	# DynaLoader calls dl_load_flags as a static method.
	*dl_load_flags = DynaLoader->can('dl_load_flags');

	do {__PACKAGE__->can('bootstrap') ||
		\&DynaLoader::bootstrap}->(__PACKAGE__,$VERSION);
}

1;

__END__

=head1 NAME

Crypt::OpenSSL::PKCS12 - Perl extension to OpenSSL's PKCS12 API.

=head1 SYNOPSIS

  use Crypt::OpenSSL::PKCS12;

  my $pass   = "your password";
  my $pkcs12 = Crypt::OpenSSL::PKCS12->new_from_file('cert.p12');

  print $pkcs12->certificate($pass);

  if ($pkcs12->mac_ok($pass)) {
	....

  $pkcs12->create('test-cert.pem', 'test-key.pem', $pass, 'out.p12', "friendly name");

=head1 ABSTRACT

  Crypt::OpenSSL::PKCS12 - Perl extension to OpenSSL's PKCS12 API.

=head1 DESCRIPTION

  This implement a small bit of OpenSSL's PKCS12 API.

=head2 EXPORT

None by default.

On request:

	NOKEYS NOCERTS INFO CLCERTS CACERTS

=head1 SEE ALSO

OpenSSL(1), Crypt::OpenSSL::X509, Crypt::OpenSSL::RSA, Crypt::OpenSSL::Bignum

=head1 AUTHOR

Dan Sully, E<lt>daniel@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2004-2007 by Dan Sully

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut
