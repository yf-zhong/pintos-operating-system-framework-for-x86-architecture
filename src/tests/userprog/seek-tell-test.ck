# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(seek-tell-test) begin
(seek-tell-test) end
seek-tell-test: exit(0)
EOF
pass;
