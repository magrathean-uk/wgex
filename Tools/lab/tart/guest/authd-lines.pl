#!/usr/bin/perl
# SPDX-License-Identifier: MIT
# M03-T11 AUTH-REAL: from `/usr/bin/log show --style compact` lines of authd on stdin, keep the evaluation lines of one right.
# A line naming the right selects its engine; that engine's lines are kept only when they match the allowlist below,
# so nothing but authd's fixed phrases, the right, client paths and engine numbers leaves the guest. At most 40 lines.
# Two passes: on macOS 27.2 (live run 7) the engine's credential and mechanism lines name the rule
# (authenticate-admin-nonshared), and the first line naming the right in authd's default level is the final
# Failed/Succeeded line, so the engine is known only after its earlier lines.
use strict;
use warnings;
my $right = shift @ARGV // die "right required\n";
$right =~ /\Acom\.magrathean\.WGEXApp\.manage-protection(?:\.dev)?\z/ or die "WGEX right required\n";
my @allow = (
  qr/Validating (?:shared credential|session owner|credential) \S+ \(\d+\) for (?:\Q$right\E|authenticate-admin-nonshared) \(engine \d+\)/,
  qr/(?:Shared credential|session owner|credential) \d+ (?:is member of group \S+ )?\((?:does|does NOT) satisfy rule\) \(engine \d+\)/,
  qr/credential \d+ expired '[0-9.]+ > \d+' \(does NOT satisfy rule\) \(engine \d+\)/,
  qr/engine \d+: running mechanism builtin:authenticate(?:,privileged)? \(\d+ of \d+\)/,
  qr/Evaluate cancelled or failed -?\d+ \(engine \d+\)/,
  qr/(?:Failed to authorize|Succeeded authorizing) right '[A-Za-z0-9._-]+' by client '[^']{1,200}' \[\d+\] for authorization created by '[^']{1,200}' \[\d+\] \([0-9,]+\) (?:\(-?\d+\) )?\(engine \d+\)/,
);
my (%engines, %seen, @lines, @kept);
while (my $line = <STDIN>) {
  chomp $line;
  next unless $line =~ /\A(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\s+\S+\s+authd\[\d+:[0-9a-f]+\] \[com\.apple\.Authorization:authd\] (.*)\z/;
  my ($stamp, $message) = ($1, $2);
  my ($engine) = $message =~ /engine (\d+)/;
  next unless defined $engine;
  # Live run 9: `/usr/bin/log show` printed each authd line twice; an exact repeat is kept once.
  next if $seen{"$stamp $message"}++;
  $engines{$engine} = 1 if index($message, $right) >= 0;
  push @lines, [$stamp, $message, $engine];
}
for my $item (@lines) {
  my ($stamp, $message, $engine) = @$item;
  next unless $engines{$engine};
  for my $pattern (@allow) {
    if ($message =~ /\A$pattern\z/) {
      push @kept, "$stamp $message";
      last;
    }
  }
}
splice(@kept, 0, @kept - 40) if @kept > 40;
print "$_\n" for @kept;
printf "authd-lines: kept=%d engines=%s\n", scalar(@kept), join(',', sort { $a <=> $b } keys %engines);
