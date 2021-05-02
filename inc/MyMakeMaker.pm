package inc::MyMakeMaker;

use Moose;
use File::Spec;

extends 'Dist::Zilla::Plugin::MakeMaker::Awesome';

override _build_WriteMakefile_args => sub {
    my $inc;
    my $libs;
    my $ccflags;

    if ($^O ne 'MSWin32' and my $prefix = `brew --prefix openssl 2>@{[File::Spec->devnull]}`) {
        chomp $prefix;

        $inc  = "-I$prefix/include";
        $libs = "-L$prefix/lib -lcrypto -lssl";
    } else {
        $inc = '-I/usr/local/opt/openssl/include -I/usr/local/include/openssl -I/usr/include/openssl -I/usr/local/include/ssl -I/usr/local/ssl/include';
        $libs = '-L/usr/local/opt/openssl/lib -L/usr/local/lib -L/usr/lib -L/usr/local/ssl/lib -lcrypto -lssl';
    }

    if ($^O =~ m/darwin/i) {
        $ccflags = '-O2 -g -Wall -Werror -Wno-deprecated-declarations -Wno-deprecated-declarations';
     } else {
        $ccflags = '-O2 -g -Wall -Werror';
     }

    return +{
        # Add LIBS => to WriteMakefile() args
        %{ super() },
        LIBS    => $libs,
        INC     => $inc,
        CCFLAGS => $ccflags,
    }
};

__PACKAGE__->meta->make_immutable;
