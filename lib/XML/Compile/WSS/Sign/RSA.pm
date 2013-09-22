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

=option  private_key OBJECT|STRING|FILENAME
=default private_key C<undef>
Required if you want to use this object to sign. See M<privateKey()>

=option  public_key  OBJECT|STRING|FILENAME
=default public_key  <from private key>
Required if you want to use this object to M<check()>. See M<publicKey()>
Usually, you need either the public or the private key, not both.  However,
when you specify a private key, you can ask for the public key as well: it
is included.

=option  hashing 'SHA1'|'MD5'|...
=default hashing <undef>

=option  padding 'NO'|'PKCS1'|...
=default padding <undef>

=cut

sub init($)
{   my ($self, $args) = @_;
    $self->SUPER::init($args);

    $self->privateKey
      ( $args->{private_key}
      , hashing => $args->{hashing}
      , padding => $args->{padding}
      );
 
    $self->publicKey
      ( $args->{public_key}
      , hashing => $args->{hashing}
      , padding => $args->{padding}
      );
    $self;
}

#-----------------
=section Attributes
=cut

=method privateKey [KEY, OPTIONS]
The private key must be set with M<new(private_key)> or this method before
you can sign.  This method will return the text of the key.
=over 4
=item * an M<Crypt::OpenSSL::RSA> object
=item * PEM formatted key, as accepted by M<Crypt::OpenSSL::RSA> method C<new_private_key()>
=item * a filename which contains such bytes.
=back

=option  hashing 'SHA1'|'MD5'|'RIPEMD160'|...
=default hashing <undef>
Enforce an hashing setting on the KEY.

=option  padding 'NO'|'PKCS1'|'PKCS1_OAEP'|'SSLv23'
=default padding <undef>
=cut

sub _setRSAflags($$%)
{   my ($self, $key, $rsa, %args) = @_;
    if(my $hashing = $args{hashing})
    {   my $use_hash = "use_\L$hashing\E_hash";
        $rsa->can($use_hash)
            or error __x"hash {type} not supported by {pkg}"
                , type => $hashing, pkg => ref $key;
        $rsa->$use_hash();
    }

    if(my $padding = $args{padding})
    {   my $use_pad = "use_\L$padding\E_padding";
        $rsa->can($use_pad)
            or error __x"padding {type} not supported by {pkg}"
                , type => $padding, pkg => ref $key;
        $rsa->$use_pad();
    }
    $rsa;
}

sub privateKey(;$%)
{   my ($self, $priv) = (shift, shift);
    defined $priv or return $self->{XCWSR_privkey};

    my ($key, $rsa) = $self->toPrivateSHA($priv);
    $self->{XCWSR_privrsa} = $self->_setRSAflags($key, $rsa, @_);
    $self->{XCWSR_privkey} = $key;
    $key;
}

=ci_method toPrivateSHA PRIVATE-KEY
=cut

sub toPrivateSHA($)
{   my ($self, $priv) = @_;

    return ($priv->get_private_key_string, $priv)
        if blessed $priv && $priv->isa('Crypt::OpenSSL::RSA');

    error __x"unsupported private key object `{object}'", object=>$priv
       if ref $priv =~ m/Crypt/;

    return ($priv, Crypt::OpenSSL::RSA->new_private_key($priv))
        if index($priv, "\n") >= 0;

    my $key = read_file $priv;
    my $rsa = Crypt::OpenSSL::RSA->new_private_key($key);
    ($key, $rsa);
}

=method privateKeyRSA
Returns the private key wrapped in a M<Crypt::OpenSSL::RSA> object.
=cut

sub privateKeyRSA() {shift->{XCWSR_privrsa}}

=method publicKey [KEY, [OPTIONS]]
Set the public key.  You can pass a KEY, which is one of
=over 4
=item * an M<XML::Compile::WSS::SecToken::X509v3> object
=item * an M<Crypt::OpenSSL::RSA> object
=item * an M<Crypt::OpenSSL::X509> object
=back
=cut

sub publicKey(;$%)
{   my $self = shift;
    my $pub   = @_%2==1 ? shift : undef;

    return $self->{XCWSR_pubkey}
        if !defined $pub && $self->{XCWSR_pubkey};

    my $token = $pub || $self->privateKeyRSA
        or return;

    my ($key, $rsa) = $self->toPublicRSA($token);
    $self->{XCWSR_pubrsa} = $self->_setRSAflags($key, $rsa, @_);
    $self->{XCWSR_pubkey} = $pub;
    $pub;
}

=ci_method toPublicRSA OBJECT
=cut

sub toPublicRSA($)
{   my ($thing, $token) = @_;
    defined $token or return;

    blessed $token
        or panic "expects a public_key as object, not ".$token;

    return ($token->get_public_key_string, $token)
        if $token->isa('Crypt::OpenSSL::RSA');

    $token = $token->certificate
        if $token->isa('XML::Compile::WSS::SecToken::X509v3');

    my $key = $token->pubkey;
    return ($key, Crypt::OpenSSL::RSA->new_public_key($key))
        if $token->isa('Crypt::OpenSSL::X509');

    error __x"unsupported public key `{token}' for check RSA"
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

# Do we need next 4?  Probably not

sub sign(@)
{   my ($self, $text) = @_;
    my $priv = $self->privateKeyRSA
        or error "signing rsa requires the private_key";

    $priv->sign($text);
}

sub encrypt(@)
{   my ($self, $text) = @_;
    my $pub = $self->publicKeyRSA
        or error "encrypting rsa requires the public_key";
    $pub->encrypt($text);
}

sub decrypt(@)
{   my ($self, $text) = @_;
    my $priv = $self->privateKeyRSA
        or error "decrypting rsa requires the private_key";
    $priv->decrypt($text);
}

=method check BYTES, SIGNATURE
=cut

sub check($$)
{   my ($self, $text, $signature) = @_;
    my $rsa = $self->publicKeyRSA
        or error "checking signature with rsa requires the public_key";

    $rsa->verify($text, $signature);
}

### above functions probably not needed.

sub builder()
{   my ($self) = @_;
    my $priv   = $self->privateKeyRSA
        or error "signing rsa requires the private_key";

    sub { $priv->sign($_[0]) };
}

sub checker()
{   my ($self) = @_;
    my $pub = $self->publicKeyRSA
        or error "checking signature with rsa requires the public_key";

    sub { # ($text, $signature)
        $pub->verify($_[0], $_[1]);
    };

#sub {
#    my ($text, $sig) = @_;
#   warn "TEXT=$text; ", ref $text;
#    my $t = $pub->verify($text, $sig);
#    $t or warn "SIGATURE FAILED";
#    1;
#    };

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
