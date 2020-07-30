OUTPUT_FORMAT("binary");

SECTIONS
{
    . = 0x0000;
    .header : {
        LONG(0)
        SHORT(_sstart)
        SHORT(__exit)
        SHORT(_etext - _sstart)
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

    /* Remove sections that won't be relevant to us */
    /DISCARD/ : {
        *(*);
    }
}
