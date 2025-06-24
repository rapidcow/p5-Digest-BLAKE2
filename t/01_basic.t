# vim: set expandtab ts=4 sw=4 nowrap ft=perl ff=unix :
use strict;
use warnings;
use Test::More;

use Digest::BLAKE2 qw/
  blake2b blake2b_hex blake2b_base64 blake2b_base64url blake2b_ascii85
  blake2s blake2s_hex blake2s_base64 blake2s_base64url blake2s_ascii85
  /;

my @targets = qw/
  kikisan kikisan_peropero
  /;
my %algorithm_results = (
    'blake2b' => [
        qw/
          852829DA8DE03AC213D69B46766900CE838706567B96CE0543D297900D0882450E440B3BEBB443526D91956606F5FB606E97DDB83F7781B85D32FD248C4F9896
          8C9235324E7D45882CD8975C0E82EF856FF85A10EED6ED49EDF969FB4EB9738BFCB3120FCF2E0FC6C9E36B098DE1C013DDB0C9FD631B46574A6E11768C9B3407
          /
    ],
    'blake2s' => [
        qw/
          02D5CB3F6740946AA74D7982A9610C83517E23DFE7B4E6DA763400FC327808B9
          E4A11A134228BFF5AF16FEB6ECD04E0F23BB86245460883C27324DEA12A9A880
          /
    ],
);
my %type_filters = (
    '' => sub {
        pack("H*", $_[0]);
    },
    '_hex' => sub {
        $_[0];
    },
);
eval q{ use MIME::Base64 };
unless ($@) {
    $type_filters{'_base64'} = sub {
        my $b64 = encode_base64(pack("H*", $_[0]), '');
        $b64 =~ s/=+$//;
        $b64;
    };
    $type_filters{'_base64url'} = sub {
        my $b64 = encode_base64(pack("H*", $_[0]), '');
        $b64 =~ tr{+/}{-_};
        $b64 =~ s/=+$//;
        $b64;
    };
}
eval q{ use Convert::Ascii85 };
unless ($@) {
    $type_filters{'_ascii85'} = sub {
        Convert::Ascii85::encode(
            pack("H*", $_[0]),
            +{ compress_zero => 0, 'compress_space' => 0 }
        );
    };
}

# https://github.com/Perl/perl5/issues/16200#issuecomment-544092140
sub starts_with {
    my ($base, $prefix) = @_;
    rindex($base, $prefix, 0) == 0;
}

for my $algorithm (keys %algorithm_results) {
    my %results;
    @results{@targets} = @{ $algorithm_results{$algorithm} };

    subtest "Function interfaces for $algorithm" => sub {
        for my $target (keys %results) {
            my $expected_hex = $results{$target};

            for my $type (keys %type_filters) {
                my $func_name = $algorithm . $type;
                my $expected  = $type_filters{$type}->($expected_hex);

                my $func = main->can($func_name);
                ok($func);
                is($func->($target), $expected, "$func_name('$target')");
            }
        }
    };

    subtest "Object interfaces via Digest::BLAKE2 for $algorithm" => sub {
        for my $target (keys %results) {
            my $expected_hex = $results{$target};

            my $instance = Digest::BLAKE2->new($algorithm);
            $instance->add($target);
            is($instance->digest, pack('H*', $expected_hex));
        }
    };

    my $module_name = $algorithm;
    $module_name =~ s/^blake2/BLAKE2/;
    $module_name = "Digest::$module_name";

    subtest "Object interfaces via $module_name" => sub {
        for my $target (keys %results) {
            my $expected_hex = $results{$target};

            my $instance = $module_name->new;
            $instance->add($target);
            is($instance->digest, pack('H*', $expected_hex));
        }

        # The following test is the same, except we test
        # the instance method to see the previous state has
        # been properly cleared and does not affects the hash.
        {
            my $persistent_instance = $module_name->new;
            $persistent_instance->add("JUNK");
            for my $target (keys %results) {
                my $expected_hex = $results{$target};

                $persistent_instance = $persistent_instance->new;
                $persistent_instance->add($target);
                my $digest = $persistent_instance->digest;
                my $expect = pack('H*', $expected_hex);
                is($digest, $expect, "$algorithm, instance new()");
            }
        }

        # Repeat the same for clone().  We exploit the fact
        # that the first string is a prefix of the second.
        {
            my ($short_str, $long_str) = @targets;
            starts_with($long_str, $short_str) or die "Assertion failed";

            my $instance = $module_name->new;
            $instance->add($short_str);
            my $instcopy = $instance->clone;
            $instcopy->add(substr($long_str, length $short_str));

            # Postpone inspection of the $short_digest so
            # the side effects of clone() would be visible
            my $short_digest = $instance->digest;
            my $long_digest = $instcopy->digest;

            is($short_digest, $results{$short_str}, "$algorithm, cloned instance");
            is($long_digest, $results{$long_str}, "$algorithm, clone instance");
        }
    };
} ## end for my $algorithm (keys %algorithm_results)

done_testing;
