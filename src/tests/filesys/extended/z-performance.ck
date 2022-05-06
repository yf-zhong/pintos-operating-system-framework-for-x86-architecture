# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(z-performance) begin
(z-performance) create "test"
(z-performance) open "test"
(z-performance) reading "test"
(z-performance) close "test"
(z-performance) open "test"
(z-performance) reading "test"
(z-performance) close "test"
(z-performance) remove "test"
(z-performance) end
EOF
pass;
