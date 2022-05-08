# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(file-size) begin
(file-size) end
file-size: exit(0)
EOF
pass;
