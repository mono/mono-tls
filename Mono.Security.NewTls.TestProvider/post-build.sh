#!/bin/sh
OUTPUTDIR=$1

ASMS="System.Threading.Tasks.dll System.Text.Encoding.dll System.IO.dll"

for asm in $ASMS; do rm -f $OUTPUTDIR/$asm; done


