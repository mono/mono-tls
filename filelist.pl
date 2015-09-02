#!/usr/bin/perl -wT
use strict;

my $prefix = "..\\..\\Mono.Security.NewTls";

while (my $line = <>) {
	chop $line;
	next unless $line =~ m,<Compile Include="(.*)"\s*/>,;
	my $file = $1;
	print "  <Compile Include=\"$prefix\\$file\">\n    <Link>$file</Link>\n  </Compile>\n";
}