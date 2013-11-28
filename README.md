SQLiteZer
=========

A forensic SQLite 3 database analysis tool. Parse out DB unallocated space to recover deleted data, directly export active cell content (bypassing the SQL parser), automatically summarize database object statistics, and expose all the juicy technical info any self-respecting reverse engineer might want. Written in Python 2.7.

	usage: SQLitezer.py [-h] -i INPUT -o OUTPUT [-a] [-c] [-m] [-u] [-x]

	optional arguments:
	-h, --help            show this help message and exit
	-i INPUT, --input INPUT
                        Target SQLite database file.
	-o OUTPUT, --output OUTPUT
                        Output job name (exclude file extension).
	-a, --active          OPTIONAL: Dump all raw active records into a CSV.
	-c, --content         OPTIONAL: Generate content report.
	-m, --pagemap         OPTIONAL: Print a visual map of the physical page
                        distribution (work in progress).
	-u, --unalloc         OPTIONAL: Dump all unallocated areas of each page into
                        a TSV.
	-x, --debug           OPTIONAL: Developers Only - Enable debug mode.
