# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(z-test) begin
(z-test) create "coalesce"
(z-test) open "coalesce"
(z-test) writing "coalesce"
(z-test) close "coalesce"
(z-test) open "coalesce"
(z-test) reading "coalesce"
(z-test) close "coalesce"
(z-test) remove "coalesce"
(z-test) end
EOF
pass;
