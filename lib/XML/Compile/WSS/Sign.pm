use warnings;
use strict;

package XML::Compile::WSS::Sign;

use Log::Report 'xml-compile-wss-sig';

use XML::Compile::WSS::Util   qw/:wss11 :dsig/;
use Scalar::Util              qw/blessed/;

my ($signs, $sigmns) = (DSIG_NS, DSIG_MORE_NS);
my $sign_algorithm   = qr/^(?:$signs|$sigmns)([a-z0-9]+)\-([a-z0-9]+)$/;

=chapter NAME
XML::Compile::WSS::Sign - Base for WSS Signers

=chapter SYNOPSIS

  # either
  use XML::Compile::WSS::Util qw/DSIG_RSA_SHA1/;
  my $sign = XML::Compile::WSS::Sign->new
    ( type        => DSIG_RSA_SHA1
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

=c_method new OPTIONS

=option   type TYPE
=default  type DSIG_RSA_SHA1

=cut

sub new(@)
{   my $class = shift;
    my $args  = @_==1 ? shift : {@_};
    my $type  = delete $args->{type} || DSIG_RSA_SHA1;

    if($class eq __PACKAGE__)
    {   $type =~ $sign_algorithm
            or error __x"unsupported sign algorithm `{algo}'", algo => $type;

        my $algo = uc $1;;
        $args->{hashing} ||= uc $2;
        $class .= '::'.$algo;

        eval "require $class"; panic $@ if $@;
    }

    (bless {XCWS_type => $type}, $class)->init($args);
}

sub init($)
{   my ($self, $args) = @_;
    $self;
}

=c_method fromConfig CONFIG, [PRIVKEY]
Try to be very flexible.  CONFIG can be a HASH, which could also be
passed to M<new()> directly.  But it can also be various kinds of
objects.
=cut

sub fromConfig($;$)
{   my ($class, $config, $priv) = @_;
    defined $config
        or return undef;

    if(ref $config eq 'HASH')
    {   $config->{private_key} ||= $priv;
        return $class->new($config);
    }

    return $class->new({type => $config, private_key => $priv})
        if !ref $config && $config =~ $sign_algorithm;

    blessed $config
        or panic "signer configuration requires HASH, OBJECT or TYPE.";

    if($config->isa(__PACKAGE__))
    {    $config->privateKey($priv) if $priv;
         return $config
    }

    panic "signer configuration `$config' not recognized";
}

#-----------------
=section Attributes
=method type
=cut

sub type() {shift->{XCWS_type}}

#-----------------
=section Handlers

=method sign ref-BYTES
Returns a SIGNATURE

=method check TOKEN, ref-BYTES, SIGNATURE
Use TOKEN to check whether the BYTES (passed by reference) match the
SIGNATURE.  TOKEN is signer specific.
=cut

sub check() {panic "not extended"}

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
