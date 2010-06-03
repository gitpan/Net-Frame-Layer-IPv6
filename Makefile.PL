#
# $Id: Makefile.PL 24 2010-06-03 12:43:58Z gomor $
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
      Net::Frame  => 0,
      Bit::Vector => 0,
   },
);
