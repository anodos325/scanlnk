/*  
   Copyright (C) iXsystems 2019.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/ 
#include <sys/types.h>
#include <errno.h>
#include <sys/stat.h>
#include <err.h>
#include <fts.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>

#define ZERO_STRUCT(x) memset_s((char *)&(x), sizeof(x), 0, sizeof(x))

struct scanlnk_info {
	char	*path;
	int	action;
	dev_t root_dev;
};

struct enum_list {
	int value;
	const char *name;
};

enum si_action {SI_FULL, SI_QUICK};

static const struct enum_list si_action[] = {
	{SI_FULL, "full"},	/* Full scan for symlinks */
	{SI_QUICK, "quick"},	/* Quick symlink scan */
	{ -1, NULL}
};

static int
get_enum(const char *s, const struct enum_list *_enum)
{
	int i;

	if (!s || !*s || !_enum) {
		return (-1);
	}

	for (i=0; _enum[i].name; i++) {
		if (strcmp(_enum[i].name,s) == 0)
			return _enum[i].value;
	}

	return (-1);
}

static void
setarg(char **pptr, const char *src)
{
	char *ptr;

	ptr = *pptr;
	if (ptr != NULL)
		free(ptr);
	ptr = strdup(src);
	if (ptr == NULL)
		err(EX_OSERR, NULL);

	*pptr = ptr;
}

static void
free_scanlnk_info(struct scanlnk_info *si)
{
	if (si == NULL)
		return;
	free(si->path);
	free(si);
}

static void
usage(char *path)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS] ...\n"
		"Where option is:\n"
		"    -a <full|quick>	 # type of scan to perform\n"
		"    -p <path>		 # path to scan\n",
		path
	);

	exit(0);
}

static void
usage_check(struct scanlnk_info *w)
{
        if (w->path == NULL)
                errx(EX_USAGE, "no path specified");
}

static int
fts_compare(const FTSENT * const *s1, const FTSENT * const *s2)
{
	return (strcoll((*s1)->fts_name, (*s2)->fts_name));
}

static int
symlink_check(struct scanlnk_info *si, FTSENT *fts_entry)
{
	int ret;
	char *path = NULL;
	struct stat st;

	path = fts_entry->fts_path;
	ZERO_STRUCT(st);
	ret = stat(path, &st);
	if (ret != 0) {
		warnx("%s: lstat failed",path);
		return ret; 
	}
	if (st.st_dev == si->root_dev) {
		fprintf(stderr, "%s\t|symlink to boot device|\n", path); 
		if (si->action == SI_QUICK) {
			return ELOOP;
		}
	}
	return ret;
}

static int
scan_links(struct scanlnk_info *si)
{
	int rval, options;
	FTS *tree = NULL;
	FTSENT *entry = NULL;
	rval = options = 0;
	char *paths[2];
	bool has_symlink;

	if (si == NULL) {
		return EINVAL;		
	}
	
	paths[0] = si->path;
	paths[1] = NULL;
	tree = fts_open(paths, options, fts_compare);
	if (tree == NULL) {
		err(EX_OSERR, "fts_open");
	}
	for (rval = 0; (entry = fts_read(tree)) != NULL;) {
		switch (entry->fts_info) {
			case FTS_SL:
				rval = symlink_check(si, entry);
				if (rval == ELOOP) {
					has_symlink = true;
				}
				if (si->action != SI_QUICK) {
					rval = 0;
				}
				break;
			case FTS_ERR:
				warnx("FTS error %s: %s",
				      entry->fts_path,
				      strerror(entry->fts_errno));
				rval = entry->fts_errno;
				break;
			default:
				break;
		}
		if (rval != 0) {
			break;
		}
	}
	if (has_symlink) {
		rval = ELOOP;
	}
	return rval; 
}

int
main(int argc, char **argv)
{
	int ch, ret;
	struct scanlnk_info *si = NULL;
	struct stat st;
	si = calloc(1, sizeof(struct scanlnk_info));
	ZERO_STRUCT(st);
	while ((ch = getopt(argc, argv, "a:p:")) != -1) {
		switch(ch) {
		case 'a': {
			int action = get_enum(optarg, si_action);
			if (action == -1) {
				errx(EX_USAGE, "invalid action");
			}
			si->action |= action;
			break;
		}
		case 'p':
			setarg(&si->path, optarg);
			break;
		case '?':
		default:
			usage(argv[0]);
		}
	}
	usage_check(si);

	if (stat("/", &st) < 0) {
		warn("%s: stat() failed.", "/");
		return (1);
	}
	si->root_dev = st.st_dev;
	ret = scan_links(si);
	free_scanlnk_info(si);
	return ret;
}
