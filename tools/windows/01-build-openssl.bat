perl -pi -e "s,/O2,/O1 /GL,g"             Configurations/10-main.conf
perl -pi -e "s,/opt:ref,/ltcg /opt:ref,g" Configurations/10-main.conf
perl Configure VC-WIN64A --prefix=%CRYPTOSHARK_PREFIX% no-shared no-unit-test
nmake install_sw
