use warnings;
use strict;

package XML::Compile::WSS::Sign::RSA;
use base 'XML::Compile::WSS::Sign';

use Log::Report 'xml-compile-wss-sig';

use Crypt::OpenSSL::RSA ();
use File::Slurp         qw/read_file/;
use Scalar::Util        qw/blessed/;

=chapter NAME
XML::Compile::WSS::Sign::RSA - WSS Signing with RSA

=chapter SYNOPSIS

  # either
  use XML::Compile::WSS::Util qw/DSIG_RSA_SHA1/;
  my $sign = XML::Compile::WSS::Sign->new(type => DSIG_RSA_SHA1);

  # or
  use XML::Compile::WSS::Sign::RSA;
  my $token = XML::Compile::WSS::Sign::RSA->new(
     hashing => 'SHA1', ...);

=chapter DESCRIPTION

=chapter METHODS

=section Constructors

=c_method new OPTIONS
=option  hashing STRING
=default hashing <derived from type>
For instance, C<SHA1>.

=option  private_key OBJECT|STRING|FILENAME
=default private_key C<undef>
Required if you want to use this object to M<sign()>. See M<privateKey()>

=option  public_key  OBJECT|STRING|FILENAME
=default public_key  <from private key>
Required if you want to use this object to M<check()>. See M<publicKey()>
Usually, you need either the public or the private key, not both.  However,
when you specify a private key, you can ask for the public key as well: it
is included.

=cut

sub init($)
{   my ($self, $args) = @_;
    $self->SUPER::init($args);
    $self->privateKey($args->{private_key}, $args->{hashing})
        if $args->{private_key};

    $self->publicKey($args->{public_key});
    $self;
}

#-----------------
=section Attributes
=method hashing
=cut

sub hashing() {shift->{XCWSR_hash}}

=method privateKey [KEY, [HASHING]]
The private key must be set with M<new(private_key)> or this method before
you can M<sign()>.  This method will return the text of the key.
=over 4
=item * an M<Crypt::OpenSSL::RSA> object
=item * PEM formatted key, as accepted by M<Crypt::OpenSSL::RSA> method C<new_private_key()>
=item * a filename which contains such bytes.
=back

=cut

sub privateKey(;$)
{   my $self    = shift;
    @_ or return $self->{XCWSR_privkey};
    my $priv    = shift;
    my $hashing = shift || 'SHA1';

    my ($key, $rsa);
    if(blessed $priv && $priv->isa('Crypt::OpenSSL::RSA'))
    {   ($key, $rsa) = ($rsa->get_private_key_string, $priv);
    }
    elsif(ref $priv)
    {   error __x"unrecognized private key object `{object}'", object => $priv;
    }
    elsif(index($priv, "\n") >= 0)
    {   ($key, $rsa) = ($priv, Crypt::OpenSSL::RSA->new_private_key($priv));
    }
    else
    {   $key = read_file $priv;
        $rsa = Crypt::OpenSSL::RSA->new_private_key($key);
    }

    my $use_hash = "use_\L$hashing\E_hash";
    $rsa->can($use_hash)
        or error __x"hash {type} not supported by {pkg}"
            , type => $hashing, pkg => ref $key;
    $rsa->$use_hash();

    $self->{XCWSR_privrsa} = $rsa;
    $self->{XCWSR_privkey} = $key;
}

=method privateKeyRSA
Returns the private key wrapped in a M<Crypt::OpenSSL::RSA> object.
=cut

sub privateKeyRSA() {shift->{XCWSR_privrsa}}

=method publicKey [KEY]
Set the public key.  You can pass a KEY, which is one of
=over 4
=item * an M<XML::Compile::WSS::SecToken::X509v3> object
=item * an M<Crypt::OpenSSL::RSA> object
=item * an M<Crypt::OpenSSL::X509> object
=back
=cut

sub publicKey(;$)
{   my $self = shift;
    @_ or return $self->{XCWSR_pubkey};

    my $token = $self->{XCWSR_pubkey} = shift || $self->privateKeyRSA;
    $self->{XCWSR_pubrsa}
      = $token->isa('Crypt::OpenSSL::RSA') ? $token
      : $token->isa('XML::Compile::WSS::SecToken::X509v3')
      ? Crypt::OpenSSL::RSA->new_public_key($token->certificate->pubkey)
      : $token->isa('Crypt::OpenSSL::X509')
      ? Crypt::OpenSSL::RSA->new_public_key($token->pubkey)
      : error __x"unsupported public key `{token}' for check RSA"
          , token => $token;
}

=method publicKeyString 'PKCS1'|'X509'
=cut

sub publicKeyString($)
{   my $rsa = shift->publicKeyRSA;
    my $how = shift || '(NONE)';

      $how eq 'PKCS1' ? $rsa->get_public_key_string
    : $how eq 'X509'  ? $rsa->get_public_key_x509_string
    : error __x"unknown public key string format `{name}'", name => $how;
}


=method publicKeyRSA
Returns the M<Crypt::OpenSSL::RSA>-wrapped public key.
=cut

sub publicKeyRSA() {shift->{XCWSR_pubrsa}}
 
#-----------------
=section Handlers
=cut

sub sign(@)
{   my ($self, $reftext) = @_;
    my $priv = $self->privateKeyRSA
        or error "signing rsa requires the private_key";
    $priv->sign($reftext);
}

=method check ref-BYTES, SIGNATURE
Use TOKEN to check whether the BYTES (passed by reference) match the
SIGNATURE.

For RSA signing, the token can be
=over 4
=item * a M<Crypt::OpenSSL::RSA> object
=item * a M<Crypt::OpenSSL::X509> object
=item * a M<XML::Compile::WSS::SecToken::X509v3> object
=back
=cut

sub check($$)
{   my ($self, $reftext, $signature) = @_;
    my $rsa = $self->publicKeyRSA
        or error "checking signature with rsa requires the public_key";

    $rsa->verify($$reftext, $signature);
}

#-----------------
=chapter DETAILS

Read DETAILS in M<XML::Compile::WSS::Sign> first.

=section Signing with RSA

=subsection Limitations

The signing algorithm uses M<Crypt::OpenSSL::RSA>.  According to its
manual-page, the current implementation is limited to 

=over 4
=item * sign_method

   DSIG_RSA_SHA1     DSIGM_RSA_MD5     DSIGM_RSA_SHA256
   DSIGM_RSA_SHA384  DSIGM_RSA_SHA512

It could support some RSA_RIPEMD160, however there is no official
constant for that in the standards.

=item * token_type

  XTP10_X509         XTP10_X509PKI

=back

=cut

1;
