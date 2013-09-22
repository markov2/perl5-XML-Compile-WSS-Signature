use warnings;
use strict;

package XML::Compile::WSS::Signature;
use base 'XML::Compile::WSS';

use Log::Report 'xml-compile-wss-sig';

use XML::Compile::WSS::Util     qw/:wss11 :wsm10 :dsig :xtp10/;
use XML::Compile::WSS::SecToken ();
use XML::Compile::WSS::Sign     ();
use XML::Compile::WSS::KeyInfo  ();
use XML::Compile::WSS::SignedInfo ();

use XML::Compile::C14N::Util    qw/:c14n/;
use XML::Compile::C14N          ();

use Digest          ();
use XML::LibXML     ();
use File::Basename  qw/dirname/;
use File::Glob      qw/bsd_glob/;
use Scalar::Util    qw/blessed/;

my %prefixes =
  ( # ds=DSIG_NS defined in ::WSS
    dsig11 => DSIG11_NS
  , dsp    => DSP_NS
  , dsigm  => DSIG_MORE_NS
  , xenc   => XENC_NS
  );

#use Data::Dumper;
#$Data::Dumper::Indent    = 1;
#$Data::Dumper::Quotekeys = 0;

=chapter NAME
XML::Compile::WSS::Signature - WSS Signatures version 1

=chapter SYNOPSIS

B<WARNING: Only limited real-life experience.>  Many optional
extensions have never been tried.

 # You may need a few of these
 use XML::Compile::WSS::Util  qw/:dsig/;
 use XML::Compile::C14N::Util qw/:c14n/;

 # This modules van be used "stand-alone" ...
 my $schema = XML::Compile::Cache->new(...);
 my $sig    = XML::Compile::WSS::Signature->new
   (sign_method => DSIG_RSA_SHA1, ...);

 # ... or as SOAP slave (strict order of object creation!)
 my $wss    = XML::Compile::SOAP::WSS->new;
 my $wsdl   = XML::Compile::WSDL11->new($wsdlfn);
 my $sig    = $wss->signature(sign_method => ...);

=chapter DESCRIPTION
The generic Web Service Security protocol is implemented by the super
class M<XML::Compile::WSS>.  This extension implements cypto signatures.

On this moment, there are two versions of this standard:
=over 4
=item F<http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/>
=item F<http://www.w3.org/TR/xmldsig-core2/>
=back

One or more elements of the document can be selected to be signed. They
are canonalized (serialized in a well-described way) and then digested
(usually via SHA1).  The digest is put in a C<SignedInfo> component of
the C<Signature> feature in the C<Security> header.  When all digests
are in place, the whole SignedInfo structure

=section Limitations
Many companies have their own use of the pile of standards for this
feature.  Some of the resulting limitations are known by the author:

=over 4
=item * digests
Only digest algorithms which are provided via the M<Digest> module are
supported for the elements to be signed.
=item * signatures
Only a limited subset of signing (algoritm, hash) combinations are
supported.  Lower on this page, you find details about each of the
provided signing implementations.
=back

=chapter METHODS

=section Constructors

=c_method new OPTIONS

The OPTIONS you provisw here, will also end-up as

=default wss_version  '1.1'

=option  signer     OBJECT|HASH|TYPE
=default signer     DSIG_RSA_SHA1
The client-side signer object, anything what is accepted by
M<XML::Compile::WSS::Sign::fromConfig()>.

=option  checker    OBJECT|HASH|TYPE
=default checker    C<undef>
The signer object with server information, anything what is accepted by
M<XML::Compile::WSS::Sign::fromConfig()>.  When provided, we do not need
to collect the information from the incoming messages.

=option  token     OBJECT|HASH|FILENAME
=default token     <depends on sign_method>
The token, anything which is accepted by
M<XML::Compile::WSS::SecToken::fromConfig()>.  This contains at least the
public information.

=option  key_info    HASH
=default key_info    {}
Read M<XML::Compile::WSS::KeyInfo::new()>

=option  signed_info HASH
=default signed_info {}
Settings for the SignedInfo structure.
Read M<XML::Compile::WSS::SignedInfo::new()>

=option  remote_token OBJECT|HASH|FILENAME
=default remote_token C<undef>
To defend against man-in-the-middle attacks, you need to specify the
server's public key.  When specified, that key will be used to verify
the signature, not the one listed in the XML response.

Only when this C<remote_token> is specified, we will require the
signature.  Otherwise, the check of the signature will only be performed
when a Signature is available in the Security header.

=requires sign_types ARRAY
Specify the types of elements which need to be signed.  If you
have more elements of the same type, they will all get signed.

=cut

sub init($)
{   my ($self, $args) = @_;
    my $wss_v = $args->{wss_version} ||= '1.1';

    $self->SUPER::init($args);

    my $signer  = delete $args->{signer} || {};
    blessed $signer || ref $signer
        or $signer  = { sign_method => $signer };            # pre 2.00
    $signer->{$_} ||= delete $args->{$_}                     # pre 2.00
        for qw/private_key/;
    $self->{XCWS_signer}  = XML::Compile::WSS::Sign
      ->fromConfig(%$signer, wss => $self);

    my $si      = delete $args->{signed_info} || {};
    $si->{$_} ||= delete $args->{$_}
        for qw/digest_method cannon_method prefix_list/;     # pre 2.00

    $self->{XCWS_siginfo} = XML::Compile::WSS::SignedInfo
      ->fromConfig(%$si, wss => $self);

    my $ki      = delete $args->{key_info} || {};
    $ki->{$_} ||= delete $args->{$_}
        for qw/publish_token/;                               # pre 2.00

    $self->{XCWS_keyinfo} = XML::Compile::WSS::KeyInfo
      ->fromConfig(%$ki, wss => $self);

    if(my $subsig = delete $args->{signature})
    {   $self->{XCWS_subsig} = (ref $self)->new(wss_version => $wss_v
          , schema => $self->schema, %$subsig);
    }

    $self->{XCWS_token}    = $args->{token};

    $self->{XCWS_config}   = $args;  # the left-overs are for me
    $self;
}

#-----------------------------

=section Attributes
=method keyInfo
=method signedInfo
=method signer
=cut

sub keyInfo()    {shift->{XCWS_keyinfo}}
sub signedInfo() {shift->{XCWS_siginfo}}
sub signer()     {shift->{XCWS_signer}}

#-----------------------------

=subsection Security Tokens
To prove the signature, there usually is some security token.  This token
may (or may not) be included in the SOAP message itself.

=method token
Returns the security token, which is an M<XML::Compile::WSS::SecToken> object.

=method remoteToken
Returns the security token of the server, which is an
M<XML::Compile::WSS::SecToken> object. Either, this token is provided
by M<new(remote_token)>, to taken from the first message.
=cut

sub token()       {shift->{XCWS_token}}
sub remoteToken() {shift->{XCWS_rem_token}}

#-----------------------------
#### HELPERS

sub prepareReading($)
{   my ($self, $schema) = @_;
    $self->SUPER::prepareReading($schema);

    my $config = $self->{XCWS_config};
    if(my $r   = $config->{remote_token})
    {   $self->{XCWS_rem_token} = XML::Compile::WSS::SecToken->fromConfig($r);
    }

    my (@elems_to_check, $container, @signature_elems);
    $schema->addHook
      ( action => 'READER'
      , type   =>  ($config->{sign_types} or panic)
      , before => sub {
          my ($node, $path) = @_;
          push @elems_to_check, $node;
          $node;
        }
      );

    # we need the unparsed node to canonicalize and check
    $schema->addHook
      ( action => 'READER'
      , type   => 'ds:SignedInfoType'
      , after  => 'XML_NODE'
      );

    # collect the elements to check, while decoding them
    $schema->addHook
      ( action => 'READER'
      , type   => ($config->{sign_put} || panic)
      , after  => sub {
          my ($xml, $data, $path) = @_;
#warn "Located signature at $path";
          push @signature_elems, $data->{ds_Signature}
              if $data->{ds_Signature};
          $container = $data;
          $data;
        }
      );

    my $check_signature = $self->checker;
    $schema->addHook
      ( action => 'READER'
      , type   => ($config->{sign_when} || panic)
      , after  => sub {
          my ($xml, $data, $path) = @_;
#warn "Checking signatures when at $path";
          @signature_elems
              or error __x"signature element not found in answer";

          # We can leave the checking via exceptions, so have to reset
          # the counters for the next message first.
          my @e = @elems_to_check;  @elems_to_check  = ();
          my @s = @signature_elems; @signature_elems = ();

          $check_signature->($container, $_, \@e) for @s;
          $data;
        }
      );

    $self;
}

# The checker routines throw an exception on error
sub checker($@)
{   my $self   = shift;
    my $config = $self->{XCWS_config};
    my %args   = (%$config, @_);

    my $si         = $self->signedInfo;
    my $si_checker = $si->checker($self, %args);
    my $get_tokens = $self->keyInfo->getTokens($self, %args);

    sub {
        my ($container, $sig, $elems) = @_;
        my $ki        = $sig->{ds_KeyInfo};
        my @tokens    = $ki ? $get_tokens->($ki, $container, $sig->{Id}) : ();

        # Hey, you try to get tokens up in the hierachy in a recursive
        # nested program yourself!
        $ki->{__TOKENS} = \@tokens;

        ### check the signed-info content

        my $info      = $sig->{ds_SignedInfo};
        $si_checker->($info, $elems, \@tokens);

        ### Check the signature of the whole block

        my $canon    = $info->{ds_CanonicalizationMethod};
        my $preflist = $canon->{c14n_InclusiveNamespaces}{PrefixList}; # || [];
        my $canonic  = $si->_get_canonic($canon->{Algorithm}, $preflist);
        my $sigvalue = $sig->{ds_SignatureValue}{_};

        my $signer   = XML::Compile::WSS::Sign->new
          ( sign_method => $info->{ds_SignatureMethod}{Algorithm}
          , public_key  => $tokens[0]
          );

        $signer->checker->($canonic->($info->{_XML_NODE}), $sigvalue)
            or error __x"received signature value is incorrect";

    };
}

sub builder(%)
{   my $self   = shift;
    my $config = $self->{XCWS_config};
    my %args   = (%$config, @_);
 
    my $signer     = $self->signer;
    my $signmeth   = $signer->signMethod;
    my $sign       = $signer->builder($self, %args);
    my $signedinfo = $self->signedInfo->builder($self, %args);
    my $keylink    = $self->keyInfo->builder($self, %args);
    my $token      = $self->token;
    my $tokenw     = $token->isa('XML::Compile::WSS::SecToken::EncrKey')
      ? $token->builder($self, %args) : undef;

    my $sigw       = $self->schema->writer('ds:Signature');

    # sign the signature!
    my $subsign;
    if(my $subsig = $self->{XCWS_subsig})
    {   $subsign = $subsig->builder;
    }

    my $unique = time;

    sub {
        my ($doc, $elems, $sec_node) = @_;
        my ($sinfo, $si_canond) = $signedinfo->($doc, $elems, $signmeth);

        $sec_node->appendChild($tokenw->($doc, $sec_node))
           if $tokenw;

        my $signature = $sign->($si_canond);
        my %sig =
          ( ds_SignedInfo     => $sinfo
          , ds_SignatureValue => {_ => $signature}
          , ds_KeyInfo        => $keylink->($doc, $token, $sec_node)
          , Id                => 'SIG-'.$unique++
          );
        my $signode   = $sigw->($doc, \%sig);
        $sec_node->appendChild($signode);

        $subsign->($doc, [$signode], $sec_node)
            if $subsign;

        $sec_node;
    };
}

sub prepareWriting($)
{   my ($self, $schema) = @_;
    $self->SUPER::prepareWriting($schema);

    $self->token
        or error __x"creating signatures needs a token";

    my $config = $self->{XCWS_config};

    my @elems_to_sign;
    $schema->addHook
      ( action   => 'WRITER'
      , type     => ($config->{sign_types} or panic)
      , after    => sub {
          my ($doc, $xml) = @_;

          unless($xml->getAttributeNS(WSU_10, 'Id'))
          {   my $wsuid = 'node-'.($xml+0);      # configurable?
              $xml->setNamespace(WSU_10, wsu => 0);
              $xml->setAttributeNS(WSU_10, Id => $wsuid);

              # Above two lines do add a xml:wsu per Id.  Below does not,
              # which is not always enough: elements live in weird places
              #  my $wsu   = $schema->prefixFor(WSU_10);
              #  $xml->setAttribute("$wsu:Id", $wsuid);
          }

#use XML::Compile::Util qw/type_of_node/;
#warn "Registering to sign ".type_of_node($xml);
          push @elems_to_sign, $xml;
          $xml;
        }
      );

    my $container;
    $schema->addHook
      ( action => 'WRITER'
      , type   => ($config->{sign_put} || panic)
      , after  => sub {
          my ($doc, $xml) = @_;
#warn "Located signature container";
#         $schema->prefixFor(WSU_10);
          $container = $xml;
        }
      );

    my $add_signature = $self->builder;
    $schema->addHook
      ( action => 'WRITER'
      , type   => ($config->{sign_when} || panic)
      , after  => sub {
          my ($doc, $xml) = @_;
#warn "Creating signature";
          $add_signature->($doc, \@elems_to_sign, $container);
          @elems_to_sign = ();
          $xml;
        }
      );

    $self;
}

sub loadSchemas($$)
{   my ($self, $schema, $version) = @_;
    return if $schema->{XCWS_sig_loaded}++;

    $self->SUPER::loadSchemas($schema, $version);

    my $xsddir = dirname __FILE__;
    trace "loading wss-dsig schemas from $xsddir/(dsig|encr)/*.xsd";

    my @xsds   =
      ( bsd_glob("$xsddir/dsig/*.xsd")
      , bsd_glob("$xsddir/encr/*.xsd")
      );

    $schema->addPrefixes(\%prefixes);
    my $prefixes = join ',', sort keys %prefixes;
    $schema->addKeyRewrite("PREFIXED($prefixes)");

    $schema->importDefinitions(\@xsds);

    $schema;
}

1;
