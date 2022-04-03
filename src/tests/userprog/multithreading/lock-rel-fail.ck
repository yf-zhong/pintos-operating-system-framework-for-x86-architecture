# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_USER_FAULTS => 1, [<<'EOF']);
(lock-rel-fail) begin
lock-rel-fail: exit(1)
EOF
pass;
