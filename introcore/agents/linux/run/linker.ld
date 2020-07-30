OUTPUT_FORMAT("binary");

SECTIONS
{
    . = 0x0000;
    .header : {
        LONG(0)
        SHORT(_sstart)
        SHORT(__exit)
        SHORT(_etext - _sstart)
        __address = .;
        QUAD(0)
    }

    .adata : {
        *(.adata);
    }

    .start : {
        _sstart = .;
        *(.start);
        _estart = .;
    }

    .text : {
        _stext = .;
        *(.text);
        _etext = .;
    }

    .rodata : {
        *(.rodata*);
    }

    .data : {
        *(.data*);
    }

    /* Remove sections that won't be relevant to us */
    /DISCARD/ : {
        *(*);
    }
}
