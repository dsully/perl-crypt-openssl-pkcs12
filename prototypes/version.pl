#!/usr/bin/env perl

use warnings;
use strict;
use feature 'say';

if ('1.10' > '1.9') {
	say "We are good, 1.10 is higher than 1.9";
} else {
	say "Darn, 1.9 is higher than 1.10";
}

if ('1.10' > '1.9') {
	say "We are good, 1.10 is higher than 1.9";
} else {
	say "Darn, 1.9 is higher than 1.10";
}

exit;