use warnings;
use strict;

package XML::Compile::WSS::KeyInfo;

use Log::Report 'xml-compile-wss-sig';

use XML::Compile::WSS::Util   qw/:wsm10 :wsm11 :xtp10/;
use XML::Compile::WSS::SecToken::X509v3 ();
use Crypt::OpenSSL::X509      qw/FORMAT_ASN1/;

=chapter NAME
XML::Compile::WSS::KeyInfo - handling WSS key info structures

=chapter SYNOPSIS
  # Not for end-users
  my $sig = XML::Compile::WSS::Signature->new(key_info => $config);
  my $ki  = $sig->keyInfo;

=chapter DESCRIPTION
The specifications define at least 10 different ways to provide security
keys to the messages.  This module implements the logic to read and write
tokens and keyinfo references to these tokens in the XML message.

=chapter METHODS

=section Constructors

=c_method new %options
End-user should use M<XML::Compile::WSS::Signature::new(key_info)> to pass
a HASH of %options.  These options do not have accessors (yet).
=cut

sub new(@) { my $class = shift; (bless {}, $class)->init({@_}) }
sub init($)
{   my ($self, $args) = @_;
    $self->{XCWK_tokens} = [];

    # It's too large to create accessors, so for this hack.
    $self->{XCWK_config} = $args;
    $self;
}

=c_method fromConfig HASH|PAIRS
Take default values to be used with the readers and writers, which
are created by this object.  So, the configuration contains all parameters
to M<builder()>
=cut

sub fromConfig(@)
{   my $class  = shift;
    $class->new(@_==1 ? %{$_[0]} : @_);  # also clones the HASH
}

#-----------------
=section Attributes

=method config
=cut

sub config() { my $c = shift->{XCWK_config}; wantarray ? %$c : $c }

#-----------------------------
=section Token administration

=method addToken $token, [$token...]
=cut

sub addToken($)
{   my $self = shift;
    push @{$self->{XCWK_tokens}}, @_;
    $self;
}

=method findToken %options

=option  fingerprint BINARY
=default fingerprint C<undef>

=option  uri   URI
=default uri   C<undef>

=option  name  STRING
=default name  C<undef>
=cut

sub findToken(%)
{   my ($self, %args) = @_;
    if(my $fu = $args{uri})
    {   foreach my $token ($self->tokens)
        {   my $tu = $token->uri or next;
            return $token if $tu eq $fu;
        }
    }
    if(my $fp = $args{fingerprint})
    {   foreach my $token ($self->tokens)
        {   my $tp = $token->fingerprint or next;
            return $token if $tp eq $fp;
        }
    }
    if(my $fn = $args{name})
    {   foreach my $token ($self->tokens)
        {   my $tn = $token->fingerprint or next;
            return $token if $tn eq $fn;
        }
    }
    ();
}

=method tokens
=cut

sub tokens() { @{shift->{XCWK_tokens}} }

#-----------------
=section Handlers

=method getTokens $wss, %options
Not for end-users.  Returns a CODE which needs to be called with a parsed
incoming message.

=cut

# See dump/keyinfo/template

sub getTokens($%)
{   my ($self, $wss) = (shift, shift);
    my %args = ($self->config, @_);

    my %keyinfo_handlers =
      ( ds_KeyName         => $self->_get_by_keyname($wss, \%args)
      , ds_KeyValue        => undef
      , ds_RetrievalMethod => undef
      , ds_X509Data        => $self->_get_as_x509data($wss, \%args)
      , ds_PGPData         => undef
      , ds_SPKIData        => undef
      , ds_MgmtData        => undef
      , wsse_SecurityTokenReference
                           => $self->_get_by_sectokref($wss, \%args)
      );

    sub {
        my ($h, $sec, $up_id) = @_;
        my $id = $h->{Id} || $up_id;
        my @tokens;
        foreach (@{$h->{cho_ds_KeyName} ||[]})
        {   my ($way, $how) = %$_;   # hash of one pair
            my $handler = $keyinfo_handlers{$way}
                or error __x"unsupported key-info type {type} for {id}"
                     , type => $way, id => $id;

            push @tokens, $handler->($id, $sec, $how);
        }
        @tokens;
    };
}

# ds_keyname
sub _get_by_keyname($$)
{   my ($self, $wss, $args) = @_;
    sub { my ($id, $sec, $h) = @_; $self->findToken(name => $h) };
}

# ds_X509Data
sub _get_as_x509data($$)
{   my ($self, $wss, $args) = @_;

    sub {
        my ($id, $sec, $h) = @_;

        my @tokens;
        foreach my $rec ( @{$h->{seq_ds_X509IssuerSerial} || []} )
        {   my $bin_cert = $rec->{ds_X509Certificate} or next;
            push @tokens, XML::Compile::WSS::SecToken::X509v3
              ->new(id => $id, binary => $bin_cert);
        }
        @tokens;
    };
}

# wsse_SecurityTokenReference
sub _get_by_sectokref($$$)
{   my ($self, $wss, $args) = @_;

    my %str_handlers =
      ( wsse_KeyIdentifier => $self->_get_str_keyid($wss, $args)
      , wsse_Reference     => $self->_get_str_uri($wss, $args)
      );

    sub {
        my ($id, $sec, $h) = @_;
        my @tokens;
        foreach (@{$h->{cho_any}})
        {   my ($ref, $d) = %$_;  # one pair
            my $handler = $str_handlers{$ref}
                or error __x"Keyinfo {id}: {type} not supported"
                     , id => $id, type => $ref;

            push @tokens, $handler->($id, $sec, $d);
        }

        @tokens;
    };
}

sub _get_str_keyid($$)  # SECTOKREF_KEYID
{   my ($self, $wss, $args) = @_;
    sub {
        my ($id, $sec, $d) = @_;
        my $valuet = $d->{ValueType};
        if($valuet eq WSM11_PRINT_SHA1)
        {   my $p  = wsm_decoded $d->{EncodingType}, $d->{_};
            return $self->findToken(fingerprint => $p);
        }

        error __x"Keyinfo {id}: {type} not supported", id => $id, type => $valuet;
    };
}

sub _get_str_uri($$)  # SECTOKREF_URI
{   my ($self, $wss, $args) = @_;
    sub {
        my ($id, $sec, $d) = @_;
        my $uri    = $d->{URI};
        my $token  = $self->findToken(uri => $uri);
        return $token if $token;   # already taken

        my $valuet = $d->{ValueType};
        if($valuet eq XTP10_X509v3)
        {   substr($uri, 0, 1) eq '#'
                or error __x"Keyinfo {id}: only inlined token references supported, got {uri}"
                    , id => $id, uri => $uri;

            my $binsec  = $sec->{wsse_BinarySecurityToken}
                or error __x"Keyinfo {id}: cannot find BinarySecurityToken"
                    , id => $id;

            my $have_id = '#'.$binsec->{wsu_Id};
            $have_id eq $uri
                or error __x"Keyinfo {id}: wrong BinarySecurityToken {uri}, expected {expect}"
                    , id => $id, uri => $have_id, expect => $uri;

            my $token   = XML::Compile::WSS::SecToken::X509v3->new
               ( id => $binsec->{wsu_Id}, uri => $uri, type => $valuet
               , binary => wsm_decoded($binsec->{EncodingType}, $binsec->{_})
               );

            $self->addToken($token);
            return $token;
        }

        panic "Keyinfo $id: $valuet not supported";
    };
}

=method builder $wss, %options
Not for end-users.  Returns a CODE which will be called to produce the
token representation in some output message.

=option  publish_token 'NO'|CONSTANTS|CODE
=default publish_token 'SECTOKREF_URI'
How to publish the security token.  The C<INCLUDE_BY_REF> constant will
add the token as BinarySecurityToken in the message, plus a keyinfo
structure with a reference to that token.  See L</DETAILS> about the
various choices and additional options they imply.

=cut

sub builder($%)
{   my ($self, $wss) = @_;
    my %args = ($self->config, @_);
    my $type = $args{publish_token} || 'SECTOKREF_URI';
    return undef if $type eq 'NO';

    my %str_handlers =
      ( KEYNAME         => '_make_keyname'
      , SECTOKREF_KEYID => '_make_sectokref_keyid'
      , SECTOKREF_URI   => '_make_sectokref_uri'
      , INCLUDE_BY_REF  => '_make_sectokref_uri'   # name is pre 2.00
      , X509DATA        => '_make_x509data'
      );

    my $handler = $str_handlers{$type}
        or panic "unknown keyinfo type $type";

    my $nest    = $self->$handler($wss, \%args);
    my $ki_id   = $args{keyinfo_id};
    sub {
        my ($doc, $token, $sec) = @_;
         +{ cho_ds_KeyName => [ $nest->($doc, $token, $sec) ]
          , Id             => $ki_id
          };
    };
}

sub _make_keyname($$$)
{   my ($self, $wss, $args) = @_;
    sub {
        my ($doc, $token, $sec) = @_;
        my $name = $token->name
            or panic "token $token has no name for KEYNAME";
        +{ ds_KeyName => $name };
    };
}

sub _make_x509data($$$)
{   my ($self, $wss, $args) = @_;
    my $as = $args->{x509data_type} || 'ASN1DER';

    my $put
      = $as eq 'ASN1DER'
      ? sub { ds_X509Certificate => $_[0]->as_string(FORMAT_ASN1) }
      : $as eq 'SERIAL'
      ? sub { ds_X509IssuerSerial =>
                { ds_X509IssuerName   => $_[0]->issuer
                , ds_X509SerialNumber => $_[0]->serial }
            }
      : $as eq 'SKI'     ? sub { ds_X509SKI => $_[0]->hash}
      : $as eq 'SUBJECT' ? sub { ds_X509SubjectName => $_[0]->subject }
      : error __x"write key-info as X509Data, unknown format `{name}'"
          , name => $as;

      # No idea how we can use this Cert Revocation List, ds_X509CRL
      # Other elements, not in ds:, not (yet) supported for writing

    # This routine can handle an ARRAY, but the rest of the module
    # probably not.
    sub {
        my ($doc, $token, $sec) = @_;
        my @data = map $put->($_)
           , ref $token eq 'ARRAY' ? @$token : $token;

        +{ seq_ds_X509IssuerSerial => \@data }
    };
}

sub _make_sectokref($$$)
{   my ($self, $wss, $args) = @_;
    my $refid  = $args->{sectokref_id};
    my $usage  = $args->{usage};
    my $refw   = $wss->schema->writer('wsse:SecurityTokenReference'
      , include_namespaces => 0);

    sub {
        my ($doc, $token, $sec, $payload) = @_;
        my $ref = $refw->($doc, +{wsu_Id => $refid, wsse_Usage => $usage
         , cho_any => $payload});
        +{ 'wsse:SecurityTokenReference' => $ref };
    };
}

sub _make_sectokref_keyid($$$)
{   my ($self, $wss, $args) = @_;

    my $valuet = $args->{keyid_value}    || WSM11_PRINT_SHA1;
    my $enct   = $args->{keyid_encoding} || WSM10_BASE64;
    my $keyid  = $args->{keyident_id};

    my $valuep;   # first param is call is $token
    if($valuet eq WSM11_PRINT_SHA1)
    {   $valuep = sub {shift->fingerprint or panic "token has no fingerprint" };
    }
    else { panic "unsupported security token reference value type '$valuet'" }

    my $encp  = sub { wsm_encoded $enct, $valuep->($_[0]) };
    my $kidw  = $wss->schema->writer('wsse:KeyIdentifier'
      , include_namespaces=>0);
    my $refer = $self->_make_sectokref($wss, $args);

    sub {
        my ($doc, $token, $sec) = @_;
        my $elem = $kidw->($doc
          , +{ wsu_Id => $keyid, ValueType => $valuet, EncodingType => $enct
             , _ => $encp->($token) });
        $refer->($doc, $token, $sec, +{'wsse:KeyIdentifier' => $elem});
     };
}

sub _make_sectokref_uri($$$)
{   my ($self, $wss, $args) = @_;

    my $schema = $wss->schema;
    my $binenc = $args->{binsec_encoding} || WSM10_BASE64;
    my $kidw   = $schema->writer('wsse:Reference', include_namespaces => 0);
    my $refer  = $self->_make_sectokref($wss, $args);
    my $bstw   = $schema->writer('wsse:BinarySecurityToken');
    my $default_uri = $args->{sectokref_uri};

    sub {
        my ($doc, $token, $sec) = @_;
        my $uri    = $default_uri || $token->uri || '#abc';
        my $intern = $uri !~ m!^\w+://!;
        my $type   = $token->type;
        my $elem   = $kidw->($doc, +{ValueType => $type, URI => $uri} );

        if($intern && $token->can('asBinary'))
        {   (my $id = $uri) =~ s/^#//;

            my $bst = $bstw->($doc,
             +{ wsu_Id       => $id
              , ValueType    => $type
              , EncodingType => $binenc
              ,  _           => wsm_encoded($binenc, $token->asBinary)
              } );
            $sec->appendChild($bst);
        }
        $refer->($doc, $token, $sec, +{'wsse:Reference' => $elem});
     };
}

#-----------------
=chapter DETAILS

=section Supported KeyInfo types

=subsection KeyInfo

On the top level, we have the following options:

  keyinfo_id STRING       an xsd:ID value for the Id attribute (namespaceless)

=subsection KEYNAME

=subsection X509DATA

This key-info type inlines one or more X509 certificates, in base64
encoding.

Additional options:

  x509data_type TYPE      read below, default ASN1DER

When you use the C<X509DATA> method to publish your key, you can specify
the C<x509data_type>

  SERIAL                  issuer name and cert serial number
  SKI                     subject key identifier (subject hash)
  SUBJECT                 subject name
  ASN1DER                  base64 encoded full public certificate
  CRL                     certification revocation list not supported (yet)

As example, you may look at M<Net::Domain::SMD::Schema>, which uses this
key storage model for an enveloped signature.

=example create X509Data key-info

  my $sig = XML::Compile::WSS::Signature->new
    ( schema     => $schemas
    , prepare    => 'WRITER'
    , ...
    , key_info   =>
        { publish_token  => 'X509DATA'
        , x509data_type  => 'SERIAL'
        };
    );

=example X509Data in a message, type=ASN1DER

  my $sig = XML::Compile::WSS::Signature->new
    ( ...
    , publish_token => 'X509DATA'   # smart use of defaults
    );

  <ds:Signature>
    ...
    <ds:KeyInfo Id="some-key-id">
      <ds:X509Data>
        <ds:X509Certificate>MII...</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>

=subsection SecurityTokenReference

The C<wsse:SecurityTokenReference> structure contains various other
constructs.  They share the following options:

   sectokref_id      the wsu:Id of the SecurityTokenReference
   usage             list of URIs

=subsection SECTOKREF_KEYID

(At least) used in EncryptedKeys structures.  The "ThumbprintSHA1" is the
SHA1 of the fingerprint of an key.

Example:

 <wsse:SecurityTokenReference>
   <wsse:KeyIdentifier
      EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
      ValueType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1">+tkVcx0cyPfbKrQtVePbC98Kjc0=</wsse:KeyIdentifier>
   </wsse:SecurityTokenReference>
 </ds:KeyInfo>

Options and defaults:

   keyid_value       WSM11_PRINT_SHA1
   keyid_encoding    WSM10_BASE64
   keyident_id       the wsu:Id of the KeyIdentifier

=subsection SECTOKREF_URI

Creates a KeyInfo structure which refers to the key via an URI.  But, this
will also add the BinarySecurityToken to the Security header, if not yet
present.

Example:

 <ds:KeyInfo Id="KI-1">
   <wsse:SecurityTokenReference wsu:Id="STR-2">
     <wsse:Reference URI="#X509-3"
        ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
   </wsse:SecurityTokenReference>
 </ds:KeyInfo>

 <wsse:Security
   <wsse:BinarySecurityToken wsu:Id="X509-3"
      EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
      ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3">
        MIIB..akDNgQ==
   </wsse:BinarySecurityToken>
 </wsse:Security>

Options and defaults:

  sectokref_uri    Relative or absolute URI

=cut

1;
