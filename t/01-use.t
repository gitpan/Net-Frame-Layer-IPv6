use Test;
BEGIN { plan(tests => 1) }

use Net::Frame::Layer::IPv6 qw(:consts);
use Net::Frame::Layer::IPv6::Fragment qw(:consts);
use Net::Frame::Layer::IPv6::Routing qw(:consts);

ok(1);
