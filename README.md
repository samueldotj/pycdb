# Introduction
*pycdb* stands for **Python Core Debugger** or **Python C Debugger**.

**pycdb** is a debugger completely written in Python using pyelftools library. It reads symbol([ELF](http://en.wikipedia.org/wiki/Executable_and_Linkable_Format)) files, parses debug([DWARF](http://en.wikipedia.org/wiki/DWARF))sections, reads coredump(elfcore) files and executes the commands given.

![Backtrace with color](https://bitbucket.org/samueldotj/pycdb/raw/master/screenshots/colored-backtrace.png)

# Features
* Input and output can be redirected.
* Color screen.
* All C data structures are represented as python class.
* More information from DWARF.
* Easy to extend or add extension since the whole debugger is in python.

## Commands

* *backtrace* - CFI walker(even if compiled -fomitframe) or stack walker(just in case needed).
* *info threads* - List all the threads in the core
* *info registers* - Provide register information of the current frame
* *list* - Display source file with syntax coloring.
* *disassemble* - Disassemble code and provide it in easy to read format.
* *thread <thread number>* - To change to different thread
* *frame <frame number>* - To change to different thread
* *examine <addr>* - To display data at the given address

### Options
* *-i* or *--interactive* - Starts an interactive session
* *-v* or *-verbose* - Increases the verbosity
* *-nc* or *--no-color* - Disable color formatting the output
* *-cl <lexer>* or *--color-lexer = <lexer>* - Select the color pygments lexer for formatting the output

### Examples

* To show backtrace **`pycdb.py backtrace`**
* To show backtrace with color **`pycdb.py list`**
* To disassemble and grep for EAX **`pycdb.py -nc disassemble | grep -i -e 'EAX'`**

### Screenshots
![Source listing](https://bitbucket.org/samueldotj/pycdb/raw/master/screenshots/list.png)
![Disassembly](https://bitbucket.org/samueldotj/pycdb/raw/master/screenshots/disassemble.png)
![Examining a data structure](https://bitbucket.org/samueldotj/pycdb/raw/master/screenshots/die.png)
![Help](https://bitbucket.org/samueldotj/pycdb/raw/master/screenshots/help.png)

## Scripting
Debugger helper functions are provided to get thread/frame/register etc. Using those functions new python programs can be written easily as needed. For example to print backtrace

    :::python
    for frame in get_threads()[0].get_frames()
        frame.populate()
        print frame.filename, frame.line, frame.function

The following program shows how to print registers from all the frames in the current thread.

    :::python
    thread = get_threads()[0]
    print 'Thread {t} registers : {r}'.format(t=thread, r=thread.get_registers())
    for frame in thread.get_frames()
        print 'Frame {f} registers : {r}'.format(f=frame, r=frame.registers)


## Interactive Mode
Interactive mode is available when started with **-i** option. It will just start a **ipython** shell. A wrapper function is provided in interactive mode to easy to run commands - **r**. For example to run backtrace in interactive mode, the developer has to type - *r 'backtrace'*.


# Credits
The following python libraries are used and without them pycdb could have not made. I like to thank authors of all these libraries and especially Eli Bendersky for [pyelftools](https://bitbucket.org/eliben/pyelftools).

* [pyelftools](https://bitbucket.org/samueldotj/pyelftools) to read elf and dwarf information.
* [ipython](http://ipython.org/) for command prompt.
* [pygments](http://pygments.org/)for syntax coloring.
* [pymsasid](http://code.google.com/p/pymsasid/) for disassembling.

