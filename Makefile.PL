use 5.00503;
use ExtUtils::MakeMaker;

WriteMakefile(
	'NAME'		=> 'Crypt::OpenSSL::PKCS12',
	'VERSION_FROM'	=> 'PKCS12.pm',
	'PREREQ_PM'		=> {},
	($] >= 5.005 ?
	(ABSTRACT_FROM => 'PKCS12.pm',
	AUTHOR     => 'Dan Sully <daniel@cpan.org>') : ()),
	'LIBS'		=> ['-lcrypto'],
	'DEFINE'	=> '-DPERL5',
	'INC'		=> '',
);
