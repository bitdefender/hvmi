OUTPUT_FORMAT("binary");

SECTIONS
{
    /* kthread agent content */
    . = 0x0000;
    .kthread_header : {
        LONG(3)
        SHORT(__skthread_trampoline)
        SHORT(__exit_kthread)
        SHORT(__ekthread_text - __skthread_text)
        QUAD(0)
    }

    .kthread_data : {
        *(.kthread_data);
    }

    .kthread_trampoline : {
        __skthread_trampoline = .;
        *(.kthread_trampoline);
        __ekthread_trampoline = .;
    }

    .kthread_text : {
        __skthread_text = .;
        *(.kthread_text);
        __ekthread_text = .;
    }

    /* add other agent here */


    /* All const string will be relocated to the end of binary */
    .rodata : {
        *(.rodata*);
    }

    /* Remove sections that won't be relevant to us */
    /DISCARD/ : {
        *(*);
    }
}
