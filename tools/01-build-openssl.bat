perl -pi.bak -e "s,/Ox /O2 /Ob2,/Os /GL,g" util\pl\VC-32.pl
perl -pi.bak -e "s,/subsystem:console /opt:ref,/subsystem:console /ltcg /opt:ref,g" util\pl\VC-32.pl
perl Configure VC-WIN32 --prefix=%CRYPTOSHARK_PREFIX%
call ms\do_nasm
nmake -f ms\nt.mak
nmake -f ms\nt.mak install
