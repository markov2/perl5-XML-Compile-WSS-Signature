#!/usr/bin/env perl
# Check decoding and encoding of wsse:BinarySecurityToken
use warnings;
use strict;

use lib '../XMLWSS/lib', 'lib';

use Log::Report mode => 2;
use Test::More;

BEGIN {
    eval "require XML::Compile::WSA";
    plan skip_all => "test requires XML::Compile::WSA" if $@;

    plan tests => 3;
}

use Data::Dumper;
$Data::Dumper::Indent    = 1;
$Data::Dumper::Quotekeys = 0;

use File::Slurp              qw/write_file/;
use MIME::Base64             qw/encode_base64/;
use XML::LibXML;

#
### Wow, we need quite a number of packages!
#

use XML::Compile::WSDL11      ();
use XML::Compile::SOAP11      ();
use XML::Compile::SOAP12      ();
use XML::Compile::Transport::SOAPHTTP ();

use XML::Compile::SOAP::WSA    ();
use XML::Compile::WSA::Util    qw/:wsa09/;

use XML::Compile::SOAP::WSS    ();
use XML::Compile::WSS::Util    qw/:xtp10 :wsm10 :wsm11 :xenc :dsig/;
use XML::Compile::C14N::Util   qw/:c14n/;

use XML::Compile::WSS::SecToken::X509v3 ();
use XML::Compile::WSS::SecToken::EncrKey ();

#
### Some private configuration
#

my $privkey1fn   = 't/20privkey.pem';
my $cert1fn      = 't/20cert.pem';

my $wsdlfn       = 't/60complex.wsdl';

my $msg_lifetime = 300;   # = 5 minutes

#
### Preparation
#

my $wss  = XML::Compile::SOAP::WSS->new(version => '1.1');
ok(defined $wss, 'WSS');

# start production of wsa headers
my $wsa  = XML::Compile::SOAP::WSA->new(version => '0.9');
ok(defined $wsa, 'WSA');

my $wsdl = XML::Compile::WSDL11->new
  ( $wsdlfn
  , prefixes => [myns => 'https://ws.example.com/']
  );
ok(defined $wsdl);

# start using the encryption key
my $pub1     = XML::Compile::WSS::SecToken::X509v3->fromFile($cert1fn);
my $pub2     = $pub1;   # lazy me!

# we can only select based on element types, not element names
my @to_sign  = qw/wsu:TimestampType SOAP-ENV:Body/;
push @to_sign, qw/wsa:AttributedURI/;         # To Action MessageId
push @to_sign, qw/wsa:EndpointReferenceType/; # ReplyTo

info "*** EncryptedKey";
my $encr_key = XML::Compile::WSS::SecToken::EncrKey->new
  ( type          => XENC_RSA_OAEP               #  w default
  , key           => '012345678'

  , signer        =>
      { sign_method   => DSIG_RSA_SHA1           #  w default
      , public_key    => $pub1                   # r  optional
      , private_key   => $privkey1fn             #  w
      }

  , key_info      =>
      { publish_token => 'SECTOKREF_KEYID'       #  w default
      , keyid_value   => WSM11_PRINT_SHA1        #  w default
      , keyid_encoding=> WSM10_BASE64            #  w default
      , keyident_id   => undef                   #  w optional
      }
  );


info "*** first signature block";
my $sig2 =
  { signed_info   =>
      { digest_method => DSIG_SHA1               #  w default
      , canon_method  => C14N_EXC_NO_COMM        #  w default
      }

  , signer        =>
      { sign_method   => DSIG_RSA_SHA1           #  w default
      , public_key    => $pub2                   # r  optional
      , private_key   => $privkey1fn             #  w default
      }

  , key_info      =>
      { publish_token => 'SECTOKREF_URI'         #  w default
      , sectoref_id   => undef                   #  w optional
      , usage         => undef                   #  w optional
      }

  , token         => $pub2
  };

info "*** second signature block";
my $sig      = $wss->signature
  ( version       => '1.1'                       # rw
  , sign_types    => \@to_sign                   # rw

  , key_info      =>
      { publish_token => 'SECTOKREF_URI'         #  w default
      , sectoref_id   => undef                   #  w optional
      , usage         => undef                   #  w optional
      }

  , signed_info   =>
      { digest_method => DSIG_SHA1               #  w default
      , canon_method  => C14N_EXC_NO_COMM        #  w default
      }

  , signer        =>
      { sign_method   => DSIG_HMAC_SHA1          #  w
      , key           => $encr_key->key          #  w
      }

  , token         => $encr_key
  , signature     => $sig2
  );

info "*** other Security headers";
# add later, because signature needs to install hooks on the types
# Actually, think that compilation should not be in 'prepare'...

# start producing wsu:Timestamp headers
my $ts       = $wss->timestamp(lifetime => $msg_lifetime);

info "*** compile calls";
$wsdl->compileCalls(transport_hook => \&fake_server);

#
### Action
#

info "*** run";

my %headers =
  ( wsa_ReplyTo   => {wsa_Address => WSA09ROLE_ANON }
  , wsa_MessageID => 'urn:uuid:bc57cb92-6a37-4e99-ad2d-1a0ad718264e'
  );

my %data    =
  ( echo          => 'Hello, World!'
  );

my ($answer, $trace) = $wsdl->call(ping => %headers, %data);

write_file 'dump/60complex/answer.dd', Dumper $answer;
#$trace->printErrors;
#$trace->printRequest(beautify => 1);

sub fake_server($$)
{  my ($request, $trace) = @_;
   my $content = $request->decoded_content;
   my $xml   = XML::LibXML->load_xml(string => $content);
   write_file 'dump/60complex/msgsent', $xml->toString(1);

   HTTP::Response->new(200, 'OK', ['Content-Type' => 'application/xml'], $content);
}


