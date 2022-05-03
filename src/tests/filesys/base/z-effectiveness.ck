# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(z-effectiveness) begin
(z-effectiveness) create "test"
(z-effectiveness) open "test"
(z-effectiveness) reading "test"
(z-effectiveness) close "test"
(z-effectiveness) open "test"
(z-effectiveness) reading "test"
(z-effectiveness) close "test"
(z-effectiveness) remove "test"
(z-effectiveness) end
EOF
pass;
