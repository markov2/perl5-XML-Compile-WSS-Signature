# This code is part of distribution XML-Compile-WSS-Signature.
# Meta-POD processed with OODoc into POD and HTML manual-pages.  See README.md
# Copyright Mark Overmeer.  Licensed under the same terms as Perl itself.

package XML::Compile::WSS::SecToken;

use warnings;
use strict;

use Log::Report 'xml-compile-wss-sig';

use XML::Compile::WSS::Util   qw/XTP10_X509v3 WSU_10 :wsm10 :wsm11 XENC_NS/;
use Scalar::Util   qw/blessed/;

=chapter NAME
XML::Compile::WSS::SecToken - Base for WSS Security Tokens

=chapter SYNOPSIS

  # either
  use XML::Compile::WSS::Util qw/XTP10_X509v3/;
  my $token = XML::Compile::WSS::SecToken->new(type => XTP10_X509v3, ...);

  # or
  use XML::Compile::WSS::SecToken::X509v3;
  my $token = XML::Compile::WSS::SecToken::X509v3->new(...);

=chapter DESCRIPTION

=section Supported token types
=over 4
=item * X509v3, see M<XML::Compile::WSS::SecToken::X509v3>
=item * An encrypted key, for instance to be used for hmac-rsa, implemented in M<XML::Compile::WSS::SecToken::EncrKey>
=back

=section Not supporter (yet)

Other token types, found in the documentation, but not (yet) supported:
=over 4
=item * LTPA: Lightweight Third Party Authentication (version 1)
=item * LTPAv2: Lightweight Third Party Authentication version 2
=back

Hire me to implement these!

=chapter METHODS

=section Constructors

=c_method new %options
=option   id     wsu::Id
=default  id     'my-token'

=option   type   TOKENTYPE
=default  type   XTP10_X509v3

=option   binary BYTES
=default  binary C<undef>

=option   fingerprint STRING
=default  fingerprint C<undef>
STRING format like C<C8:AE:B1:25:  :24:00:7A:82:F2>.  A bit weird that
this gets base64 encoded as well.

=option    uri   NAME
=default   uri   <unique>

=option    encoding WSM10*
=default   encoding WSM10_BASE64
=cut

sub new(@)
{   my $class = shift;
    my $args  = @_==1 ? shift : {@_};
    my $type  = delete $args->{type} || XTP10_X509v3;
    if($class eq __PACKAGE__)
    {   if($type =~ /509/)
        {   $class = 'XML::Compile::WSS::SecToken::X509v3';
        }
        else
        {   error __x"security token type {type} not (yet) supported"
              , type => $type;
        }
        eval "require $class"; panic $@ if $@;
    }
    (bless {XCWS_type => $type}, $class)->init($args);
}

sub init($)
{   my ($self, $args) = @_;
    $self->{XCWS_id}   = $args->{id}       || 'my-token';
    $self->{XCWS_enc}  = $args->{encoding} || WSM10_BASE64;
    $self->{XCWS_fp}   = $args->{fingerprint};
    $self->{XCWS_uri}  = $args->{uri}      || '#TOKEN-'.($self+0);
    $self->{XCWS_name} = $args->{name};
    $self;
}

=c_method fromConfig $config, %options
Try to be very flexible.  $config can be a HASH, which could also be
passed to M<new()> directly.  But it can also be various kinds of
objects.

=option  type CONSTANT
=default type XTP10_X509v3
[1.07] the type of the security token.
=cut

sub fromConfig($%)
{   my ($class, $config, %args) = @_;
    $args{type} ||= XTP10_X509v3;

    return $class->new(%$config, %args)
        if ref $config eq 'HASH';

    blessed $config
        or panic "token configuration requires HASH or OBJECT.";

    return $config
        if $config->isa(__PACKAGE__);

    return $class->new(%args, certificate => $config)
        if ref $config =~ m/::X509/;  # there are a few options here

    panic "token configuration `$config' not recognized";
}

#-----------------
=section Attributes
=method id
=method type
=method encoding

=method fingerprint
=cut

sub id()       {shift->{XCWS_id}}
sub type()     {shift->{XCWS_type}}
sub encoding() {shift->{XCWS_enc}}

sub fingerprint{shift->{XCWS_fp}}
sub uri()      {shift->{XCWS_uri}}
sub name()     {shift->{XCWS_name}}

#-----------------
=section Handlers

=method asBinary
If implemented, this token can be included as "BinarySecurityToken"
=cut

1;

__END__


*** Lightweight Third Party Authentication (LTPA)  Version 1

http://pic.dhe.ibm.com/infocenter/wasinfo/v6r1/index.jsp?topic=%2Fcom.ibm.websphere.express.doc%2Finfo%2Fexp%2Fae%2Fcwbs_binarysectoken.html
This is a WSS1.0 version (ValueType is QName)

<wsse:BinarySecurityToken xmlns:ns7902342339871340177=
  "http://www.ibm.com/websphere/appserver/tokentype/5.0.2"
     EncodingType="wsse:Base64Binary"
     ValueType="ns7902342339871340177:LTPA">
            MIZ6LGPt2CzXBQfio9wZTo1VotWov0NW3Za6lU5K7Li78DSnIK6iHj3hxXgrUn6p4wZI
            8Xg26havepvmSJ8XxiACMihTJuh1t3ufsrjbFQJOqh5VcRvI+AKEaNmnEgEV65jUYAC9
            C/iwBBWk5U/6DIk7LfXcTT0ZPAd+3D3nCS0f+6tnqMou8EG9mtMeTKccz/pJVTZjaRSo
            msu0sewsOKfl/WPsjW0bR/2g3NaVvBy18VlTFBpUbGFVGgzHRjBKAGo+ctkl80nlVLIk
            TUjt/XdYvEpOr6QoddGi4okjDGPyyoDxcvKZnReXww5UsoqlpfXwN4KG9as=
</wsse:BinarySecurityToken></wsse:Security></soapenv:Header>

*** Lightweight Third Party Authentication (LTPA)  Version 2
http://pic.dhe.ibm.com/infocenter/wasinfo/v6r1/index.jsp?topic=%2Fcom.ibm.websphere.express.doc%2Finfo%2Fexp%2Fae%2Fcwbs_binarysectoken.html
This is a WSS1.0 version (ValueType is QName)

The following example depicts an LTPA version 2 binary security token:

<wsse:BinarySecurityToken 
  xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" 
  xmlns:wsst="http://www.ibm.com/websphere/appserver/tokentype" 
  wsu:Id="ltpa_20" 
  ValueType="wsst:LTPAv2">
  bRYI0Z59k/P1gIkgSaxeJIQoI1BdojxjdoD+6qMmiH37lqS6U90Wx6EArMA05FHVyTmxvIJACGD
  UVfqVcPDQCdPlWAn9Brhz/bXw9OEVx0wx/eNYQuiBvEVNam7urd8SxZkqppOZyeN6APZ4Z4Rox0M
  jqQv9lFIB/AKBpJyaK8V9Z9gFO8k6J5HmE/G9jdBov9Su6hXlfF50Bhy6tx8BEm4Zn/pkeNc1H1d+
  tOxwDOfS0ORWH0tjzDCTFpAMPjMmfR0/o7o3DivONtZG61ylbcwB4hx01iQC/FN5DJwrEy8kCwCeF
  ywubKVVt5pyM1k6uVXI8ik5Pjf9aU1ei86y5iXc9CirhvqosXiZvjObHTYKZSjtGiMYw3q9NKbZxs
  SzfCuAdht8sjGfaVo43i0iz7CuFYAywqVldUPjwSTvCGNtmWB/3MRtBDrmq3fqYSomjw5ZWDFex/n
  98ZaOz8mUjNHinJc4APTtEx6S10CxUkUc8b8hoCdqbcOGdZcGqYF7xgcFXvsezsXw0eRmhra54x6g
  CJs1skMMNvi0vF2pic1cg4GClQ74NKxV1oTrDZPaQPTikYGJOLKHBPYnbPda0hPkX+iCOYN0IIRBa
  Vwjj1T0G+Y/MgokiNJRGwUQ7VHXEo0+Q2HsmCkmAFrIp4lZc9fGcFyVY/EUBBpkGchL0eKNv4DoVJW
  6EhFXWZdeiVk8
</wsse:BinarySecurityToken>

