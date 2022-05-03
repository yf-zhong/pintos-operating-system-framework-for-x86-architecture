# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(z-test) begin
(z-test) create "test"
(z-test) open "test"
(z-test) reading "test"
(z-test) close "test"
(z-test) open "test"
(z-test) reading "test"
(z-test) close "test"
(z-test) remove "test"
(z-test) end
EOF
pass;
