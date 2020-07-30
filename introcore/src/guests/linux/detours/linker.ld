OUTPUT_FORMAT("binary");

SECTIONS
{
    . = 0x0000;
    .detours : {
        *(.detours);
    }

    .os_specific : {
        *(.os_specific);
    }

    .text : ALIGN(0x1000){
        *(.text);
    }

    /DISCARD/ : {
        *(*);
    }
}
