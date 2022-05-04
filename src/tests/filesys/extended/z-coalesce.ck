# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(z-coalesce) begin
(z-coalesce) create "coalesce"
(z-coalesce) open "coalesce"
(z-coalesce) writing "coalesce"
(z-coalesce) close "coalesce"
(z-coalesce) open "coalesce"
(z-coalesce) reading "coalesce"
(z-coalesce) close "coalesce"
(z-coalesce) remove "coalesce"
(z-coalesce) end
EOF
pass;
