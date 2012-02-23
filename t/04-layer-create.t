use Test;
BEGIN { plan(tests => 1) }

use Net::Frame::Layer::IPv6 qw(:consts);
use Net::Frame::Layer::IPv6::Fragment qw(:consts);
use Net::Frame::Layer::IPv6::Routing qw(:consts);

my $l = Net::Frame::Layer::IPv6->new;
$l->pack;
$l->unpack;

$l = Net::Frame::Layer::IPv6::Fragment->new;
$l->pack;
$l->unpack;

$l = Net::Frame::Layer::IPv6::Routing->new;
$l->pack;
$l->unpack;

ok(1);
