use warnings;
use strict;

package XML::Compile::WSS::Sign::HMAC;
use base 'XML::Compile::WSS::Sign';

use Log::Report 'xml-compile-wss-sig';

use Digest::HMAC_SHA1   ();
use File::Slurp         qw/read_file/;
use Scalar::Util        qw/blessed/;

=chapter NAME
XML::Compile::WSS::Sign::HMAC - WSS Signing with HMAC

=chapter SYNOPSIS

  # either
  use XML::Compile::WSS::Util qw/DSIG_HMAC_SHA1/;
  my $sign = XML::Compile::WSS::Sign->new(type => DSIG_HMAC_SHA1);

  # or
  use XML::Compile::WSS::Sign::HMAC;
  my $token = XML::Compile::WSS::Sign::HMAC->new(
     hashing => 'SHA1', ...);

=chapter DESCRIPTION

=chapter METHODS

=section Constructors

=c_method new OPTIONS

=requires key  KEY|M<XML::Compile::WSS::SecToken::EncrKey> object

=cut

sub init($)
{   my ($self, $args) = @_;
    $self->SUPER::init($args);

    my $key = $args->{key} or error __x"HMAC signer needs a key";
    $key    = $key->key if blessed $key && $key->can('key');
    $self->{XCWSH_key} = $key;

    my $h = $args->{hashing};
    $h eq 'SHA1'
        or error __x"unsupported HMAC hashing '{hash}'", hash => $h;

    $self;
}

#-----------------
=section Attributes
=method key
=cut

sub key() {shift->{XCWSH_key}}

#-----------------
=section Handlers
=cut

sub builder(@)
{   my ($self) = @_;
    my $key    = $self->key;

    # Digest object generally cannot be reused.
    sub {
        Digest::HMAC_SHA1->new($key)->add($_[0])->digest;
    };
}

sub getCheck($$)
{   my ($self) = @_;
    my $key    = $self->key;

    sub {  # ($text, $sigature)
        Digest::HMAC_SHA1->new($key)->add($_[0])->digest eq $_[1];
    };
}

#-----------------
=chapter DETAILS

Read DETAILS in M<XML::Compile::WSS::Sign> first.

=section Signing with HMAC

=subsection Limitations

The signing algorithm uses M<Digest::HMAC_SHA1>.  Only SHA1 hashing is
supported.

=cut

1;
