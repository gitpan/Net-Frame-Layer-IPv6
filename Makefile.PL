#
# $Id: Makefile.PL 21 2009-05-31 15:17:22Z gomor $
#
use ExtUtils::MakeMaker;

require v5.6.1;

WriteMakefile(
   NAME          => 'Net::Frame::Layer::IPv6',
   VERSION_FROM  => 'lib/Net/Frame/Layer/IPv6.pm',
   LICENSE       => 'artistic',
   ABSTRACT_FROM => 'lib/Net/Frame/Layer/IPv6.pm',
   AUTHOR        => 'GomoR <gomor-cpan_at_gomor.org>',
   PREREQ_PM     => {
      Net::Frame => 0,
   },
);
