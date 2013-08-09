use warnings;
use strict;

package XML::Compile::WSS::SecToken::EncrKey;
use base 'XML::Compile::WSS::SecToken';

use Log::Report 'xml-compile-wss-sig';

use XML::Compile::WSS::Util    qw/:xenc :wsm10/;
use XML::Compile::WSS::Sign    ();
use XML::Compile::WSS::KeyInfo ();

=chapter NAME
XML::Compile::WSS::SecToken::EncrKey - WSS Encrypted Keys

=chapter SYNOPSIS

=chapter DESCRIPTION

=section Supported token types
=over 4
=item * AEOP
=back

=chapter METHODS

=section Constructors

=c_method new OPTIONS
=default  type   XENC_RSA_OAEP

=requires key    STRING
The binary key used to sign.

=requires signer HASH|M<XML::Compile::WSS::Sign>-object
This signer encrypts the key which use used, for instance, in HMAC.

=option   key_info HASH
=default  key_info <constructed>

=cut

sub init($)
{   my ($self, $args) = @_;
    $args->{type} ||= XENC_RSA_OAEP;

    $self->SUPER::init($args);

    my $type  = $self->type;
    $type eq XENC_RSA_OAEP
        or error __x"unsupported encrypted key type {type}", type => $type;

    # This can be made cleaner, via SecToken::fromConfig
    my $signer = $args->{signer}
        or error __x"EncryptedKey needs info about its signer";

    if(ref $signer eq 'HASH')
    {   $signer->{padding} ||= 'PKCS1_OAEP';
        $signer = XML::Compile::WSS::Sign->fromConfig($signer);
    }
    $self->{XCWSE_signer} = $signer;
    $self->{XCWSE_key}    = $args->{key} or panic "no key";

    my $ki      = $args->{key_info} || {};
    $ki->{publish_token} ||= 'SECTOKREF_KEYID';
    $self->{XCWSE_keyinfo} = XML::Compile::WSS::KeyInfo->fromConfig($ki);

    $self;
}

#-----------------
=section Attributes
=method signer
=method key
=method keyInfo
=cut

sub signer() {shift->{XCWSE_signer}}
sub key()    {shift->{XCWSE_key}}
sub keyInfo(){shift->{XCWSE_keyinfo}}

#-----------------
=section Handlers
=cut

# See http://en.wikibooks.org/wiki/XML_-_Managing_Data_Exchange/XML_Encryption

sub _get_encr($$)
{   my ($class, $wss, $args) = @_;
    my $keyinfo      = $wss->keyInfo;
    my $gettokens    = $keyinfo->getTokens($wss);
    my $type_default = $args->{encrtype_default};

    sub {
        my ($h, $sec) = @_;
        my $id     = $h->{Id};
        my @tokens = $gettokens->($h->{ds_KeyInfo}, $sec, $id);
        my $token  = $tokens[0]
            or error __x"no token for encryption key {id}", id => $id;

        my $type   = $h->{xenc_EncryptionMethod}{Algorithm} || $type_default;
        $type eq XENC_RSA_OAEP
            or error __x"unsupported encryption type {type}", type => $type;

        XML::Compile::WSS::SecToken::EncrKey->new
          ( id         => $id
          , type       => $type
          , key_size   => $h->{xenc_KeySize}
          , token      => $tokens[0]

          # OAEP parameters are only used by old PKCS and not supported
          # by openssl
          , params     => $h->{xenc_OAEPparams}
          );
    };
}

# The key may differ per message, not the certificate
# Do not reinstate existing encrypters

=c_method getEncrypter WSS, OPTIONS
Not for end-users.  Returns the CODE which returns the object which
handles encryption or decryption of the key.
=cut

my %encrs;
sub getEncrypter($%)
{   my ($class, $wss, %args) = @_;
    my $get_encr = $class->_get_encr($wss, \%args);

    sub {
        my ($h, $sec) = @_;
        my $id   = $h->{Id};
        $encrs{$id} ||= $get_encr->($h, $sec);
    };
}

=c_method getKey WSS, OPTIONS
Not for end-users.  Returns the CODE to produce the decrypted key.
=cut

sub getKey($%)
{   my ($class, $wss, %args) = @_;
    my $get_encr = $class->getEncrypter($wss, %args);

    sub {
        my ($h, $sec) = @_;
        my $encr = $get_encr->($h, $sec);

        # xenc_CipherReference not (yet) supported
        $h->{xenc_CipherData}{xenc_CipherValue}
            or error __x"cipher data not understood for {id}", id => $encr->id;
    };
}

=c_method getChecker WSS, OPTIONS
=cut

sub getChecker($%)
{   my ($class, $wss, %args) = @_;
    my $get_encr = $class->getEncrypter($wss, %args);

    sub {
        my ($h, $sec, $value) = @_;
        my $encr = $get_encr->($h, $sec);
        my $id   = $encr->id;

        # xenc_CipherReference not (yet) supported
        my $outcome = $h->{xenc_CipherData}{xenc_CipherValue}
            or error __x"cipher data not understood for {id}", id => $id;
#use MIME::Base64;
#warn "OUT=", encode_base64 $outcome;

        my $got = $encr->signer->encrypt($value);
#warn "GOT=", encode_base64 $got;
        $got eq $outcome
            or warning __x"check of crypto checksum failed {id}", id => $id;

        1;
    };
}

sub builder($%)
{   my ($self, $wss, %args) = @_;

    my $keylink    = $self->keyInfo->builder($wss, %args);
    my $signer     = $self->signer;
    my $encr_type  = $self->type;
    my $key        = $self->key;
    my $seckeyw    = $wss->schema->writer('xenc:EncryptedKey');

    sub {
        my ($doc, $sec_node) = @_;
        my $ki = undef; # $keylink->($doc, $signer->privateKey, $sec_node)

        # see dump/encrkey/template
        my %data =
          ( xenc_EncryptionMethod => { Algorithm => $encr_type }
          , ds_KeyInfo => $ki
          , xenc_CipherData => { xenc_CipherValue => $signer->encrypt($key) }
          );

        my $node = $seckeyw->($doc, \%data);
#warn $node->toString(1);
        $sec_node->appendChild($node);
        $node;
    };
}

1;
