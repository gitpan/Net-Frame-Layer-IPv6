eval "use Test::Pod::Coverage tests => 3";
if ($@) {
   use Test;
   plan(tests => 1);
   skip("Test::Pod::Coverage required for testing");
}
else {
   pod_coverage_ok("Net::Frame::Layer::IPv6");
   pod_coverage_ok("Net::Frame::Layer::IPv6::Fragment");
   pod_coverage_ok("Net::Frame::Layer::IPv6::Routing");
}
