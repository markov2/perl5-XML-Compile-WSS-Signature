# This code is part of distribution XML-Compile-WSS-Signature.
# Meta-POD processed with OODoc into POD and HTML manual-pages.  See README.md
# Copyright Mark Overmeer.  Licensed under the same terms as Perl itself.

package XML::Compile::WSS::Sign;

use warnings;
use strict;

use Log::Report 'xml-compile-wss-sig';

use XML::Compile::WSS::Util   qw/:wss11 :dsig/;
use Scalar::Util              qw/blessed/;

my ($signs, $sigmns) = (DSIG_NS, DSIG_MORE_NS);

=chapter NAME
XML::Compile::WSS::Sign - Base for WSS Signers

=chapter SYNOPSIS

  # either
  use XML::Compile::WSS::Util qw/DSIG_RSA_SHA1/;
  my $sign = XML::Compile::WSS::Sign->new
    ( sign_method => DSIG_RSA_SHA1
    , private_key => $key
    , ...
    );

  # or
  use XML::Compile::WSS::Sign::RSA;
  my $sign = XML::Compile::WSS::Sign::RSA->new
    ( hashing     => 'SHA1'
    , private_key => $key
    , ...
    );

=chapter DESCRIPTION

=section Supported signers
=over 4
=item * RSA
=back

Hire me to implement other signers!

=chapter METHODS

=section Constructors

=c_method new %options

=option   sign_method TYPE
=default  sign_method DSIG_RSA_SHA1

=cut

sub new(@)
{   my $class = shift;
    my $args  = @_==1 ? shift : {@_};

    $args->{sign_method} ||= delete $args->{type};      # pre 2.00
    my $algo = $args->{sign_method} ||= DSIG_RSA_SHA1;

    if($class eq __PACKAGE__)
    {   if($algo =~ qr/^(?:\Q$signs\E|\Q$sigmns\E)([a-z0-9]+)\-([a-z0-9]+)$/)
        {   my $algo = uc $1;;
            $args->{hashing} ||= uc $2;
            $class .= '::'.$algo;
        }
        else
        {    error __x"unsupported sign algorithm `{algo}'", algo => $algo;
        }
        eval "require $class"; panic $@ if $@;
    }

    (bless {}, $class)->init($args);
}

sub init($)
{   my ($self, $args) = @_;
    $self->{XCWS_sign_method} = $args->{sign_method};
    $self;
}

=c_method fromConfig HASH|PAIRS
Try to be very flexible.  CONFIG can be a HASH, which could also be
passed to M<new()> directly.  But it can also be various kinds of
objects.
=cut

sub fromConfig($)
{   my $class = shift;
    $class->new(@_==1 ? %{$_[0]} : @_);
}

#-----------------
=section Attributes
=method signMethod
=cut

sub signMethod() {shift->{XCWS_sign_method}}

#-----------------
=section Handlers

=method builder

=method checker

=cut

#-----------------
=chapter DETAILS

=section Signing, the generic part

The base of this whole security protocol is crypto-signing the messages,
so you will always need to specify some parameters for M<new()>.

  my $wss  = XML::Compile::WSS::Signature->new
    ( signer => DSIG_$algo
    , ...parameters for $algo...
    );

When the algorithm is known (see the next sections of this chapter),
then the parameters will be used to produce the CODE which will do the
signing.

=section Defend against man-in-the-middle

The signature can easily be spoofed with a man-in-the-middle attack,
unless you hard-code the remote's public key.

  my $wss  = XML::Compile::WSS::Signature->new
    ( ...
    , remote_token          => $token
    );

=cut

1;
