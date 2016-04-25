# qcheck

## What?

qcheck is a utility that takes a qcow2 file as input and attempts to validate
the header, metadata, and all data pointers for simple errors and problems like
alignment, overlaps and collisions, and a few other simple problems.

It is currently a read-only tool, it does not attempt to repair problems, just
report them in a verbose way to help identify the root cause of failure in a
corruption incident.

It does not use or attempt to invoke any qemu component, to hopefully be
slightly more tolerant of errant files.

It keeps a full map of the entire file with regards to what clusters are
metadata, guest data, vacant, leaked and so on. In the future I may augment
this with visualizations to visually "see" a qcow2's allocation pattern,
including defragmentation visualizations.

It does not currently support or attempt to validate snapshot tables or
VMState data. It probably has a lot of bugs regarding the handling and
analysis of the differences between V2/V3 qcow2 files. It was designed with
V3 images in particular in mind.

## Usage

`./qcheck [opts] <qcow2_file>`

Additional logging presets and filters can be used:

Logging presets: these are all mutually exclusive, except for debug.
<pre>
        -s --silent:  No output whatsoever.
        -q --quiet:   Fatal and nonfatal qcheck errors. (--log fw)
        -b --basic:   Basic analysis and summaries. This is the default.
                      (--log fwshiHLR)
        -v --verbose: Detailed problem analysis. (--log fwshiHLRpc)
        -x --deluge:  Everything except debug output.
        -d --debug:   The same as `--log d`.
                      `--deluge --debug` or `-xd` enables all output.
</pre>

`-l [...] --log=[...]`: detailed logging filters. Specify individual
                        output streams.
                        All filters are additive and will combine with presets.
                        e.g. `--log=fwshi`

`-e [...] --exclude=[...]`: exclude these filters.
                            Will subtract filters from presets.
                            e.g. `--basic --exclude=LHR`

The available filters for inclusion/exclusion are:
<pre>
        'f': Fatal errors
        'w': Nonfatal errors
        's': Analysis summaries
        'h': Section headers
        'i': Info / misc.
        'p': Detailed problems reports
        'c': Successful test messages (Confirmation)
        'd': Debugging messages
        'H': qcow2 header information
        'L': L1 table
        'l': L2 tables
        'R': Refcount Table
        '2': Refcount Block entries (if 2+)
        '1': Refcount Block entries (if 1)
        '0': Refcount Block entries (if 0)
        'M': Dump metadata rangeset
        'D': Dump guest data rangeset
        'V': Dump vacant rangeset
        'F': Dump leaked ([F]orgotten) rangeset
        'A': Dump allocated rangeset
        'U': Dump unallocated rangeset
        'E': Dump entire rangeset
</pre>

## License

This project makes use of Linux internals (the Red-Black trees) so by extension,
this project is GPLv2. It is also based off of the QEMU qcow2 specification,
which is also GPLv2.

If there is a licensing issue with the way I have released this project, or you
wish to borrow components isolated from the RBTree module, please contact me.

## Bugs, Contributions, Feedback

- Feel free to use the github issue tracker.
- Please also feel free to send pull requests via github.
- Please don't report issues or problems to the QEMU mailing list.